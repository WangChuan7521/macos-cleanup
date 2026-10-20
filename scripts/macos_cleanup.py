#!/usr/bin/env python3
"""Bounded macOS cache inventory and explicitly confirmed cleanup.

Uses Python's standard library and macOS /usr/bin/du. The public CLI never
accepts another home directory. Scan and plan do not mutate cleanup targets;
apply defaults to validation and dry run. A digest is a change detector, not
proof that a person has approved a plan: the calling assistant must obtain
explicit approval for the displayed paths, method, and consequences first.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import hmac
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any


VERSION = 1
MAX_SCAN_SECONDS = 180
MAX_DU_SECONDS = 20
MAX_ENUMERATED_CHILDREN = 300
MAX_CANDIDATES = 120
MAX_TREE_ENTRIES = 100_000
MAX_TREE_SECONDS = 30
MAX_TREE_DEPTH = 64
MAX_PLAN_TARGETS = 32
MAX_PLAN_ENTRIES = 200_000
MAX_PLAN_SECONDS = 120
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
FRESHNESS_SECONDS = 24 * 60 * 60
UTC = dt.timezone.utc
DIRECT_GROUPS = (
    ("app-cache", "Library/Caches"),
    ("xcode-derived-data", "Library/Developer/Xcode/DerivedData"),
)
EXACT_GROUPS = (
    ("npm-cache", ".npm/_cacache"),
    ("pip-cache", ".cache/pip"),
    ("uv-cache", ".cache/uv"),
    ("gradle-cache", ".gradle/caches"),
    ("pnpm-store", "Library/pnpm/store"),
)
REVIEW_LOCATIONS = (
    ("Xcode Archives", "Library/Developer/Xcode/Archives"),
    ("CoreSimulator", "Library/Developer/CoreSimulator"),
    ("Downloads", "Downloads"),
    ("Trash", ".Trash"),
    ("User logs", "Library/Logs"),
    ("Cargo registry", ".cargo/registry"),
    ("Maven repository", ".m2/repository"),
    ("Application Support", "Library/Application Support"),
)
DEFERRED_REVIEW_LOCATIONS = (("Codex runtime cache — deferred", ".cache/codex-runtimes"),)
CONSEQUENCES = {
    "app-cache": "App-specific review required. Quit the owning app. Cached/offline data may be lost; regeneration or downloading may be required. Some apps misuse caches for persistent data.",
    "xcode-derived-data": "Quit Xcode and builds. Build products and indexes are removed; the next build and indexing can be slow.",
    "npm-cache": "Stop package installs. Cached packages will need downloading again; offline installs may fail.",
    "pip-cache": "Stop package installs. Cached wheels and downloads will need rebuilding or downloading again.",
    "uv-cache": "Stop uv operations. Cached packages and environments may need downloading or rebuilding again.",
    "gradle-cache": "Stop Gradle builds and daemons first. Dependencies and generated caches need downloading or rebuilding; offline builds may fail.",
    "pnpm-store": "Stop package operations. Installed projects can have links into this store; later installs may need repair or downloading. Review affected projects before selecting.",
}


class SafetyError(RuntimeError):
    """A required safety condition could not be established."""


@dataclass(frozen=True)
class _Context:
    # Tests inject a temporary home here; this is deliberately not a CLI option.
    home: Path
    uid: int
    host: str

    @property
    def binding(self) -> dict[str, Any]:
        return {"home": str(self.home), "uid": self.uid, "host": self.host}


def current_context() -> _Context:
    if sys.platform != "darwin":
        raise SafetyError("Operational commands are supported only on macOS.")
    if os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise SafetyError("Run as your ordinary macOS user, without sudo or changed privileges.")
    home = _absolute(os.path.expanduser("~"))
    _check_ancestors(home)
    # kern.bootsessionuuid is unique to this boot: rebooting intentionally
    # invalidates plans. kern.uuid is the kernel build UUID and is NOT a host ID.
    try:
        boot_uuid = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], capture_output=True, timeout=3, check=True).stdout.strip()
        if not re.fullmatch(rb"[0-9A-Fa-f-]{36}", boot_uuid):
            raise ValueError("Unexpected boot UUID format")
        identity = b"boot-session:" + boot_uuid
    except (OSError, ValueError, subprocess.SubprocessError):
        try:
            # Read the UUID as metadata; never emit raw ioreg output (which can
            # include a hardware serial number) to logs or manifests.
            output = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=True).stdout
            match = re.search(rb'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"', output)
            if match is None:
                raise ValueError("No platform UUID")
            identity = b"platform:" + match.group(1)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise SafetyError("Cannot establish this Mac's machine binding.") from exc
    return _Context(home=home, uid=os.getuid(), host=hashlib.sha256(identity).hexdigest())


def _now() -> dt.datetime:
    return dt.datetime.now(UTC)


def _stamp(value: dt.datetime | None = None) -> str:
    return (value or _now()).isoformat(timespec="seconds")


def _date(value: Any) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise SafetyError("Invalid or missing timestamp.") from exc


def _fresh(value: Any, label: str) -> dt.datetime:
    parsed = _date(value)
    age = (_now() - parsed).total_seconds()
    if age < -60 or age > FRESHNESS_SECONDS:
        raise SafetyError(f"{label} is stale or dated in the future; scan and plan again.")
    return parsed


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result["digest"] = _digest(document)
    return result


def _verify_seal(document: dict[str, Any]) -> None:
    supplied = document.get("digest")
    payload = {key: value for key, value in document.items() if key != "digest"}
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, _digest(payload)):
        raise SafetyError("Document digest mismatch; scan/plan again rather than editing manifests.")


def _absolute(value: str | Path) -> Path:
    raw = os.fspath(value)
    if not os.path.isabs(raw) or ".." in Path(raw).parts or str(Path(raw)) != raw:
        raise SafetyError(f"Expected a normalized absolute path: {raw!r}")
    return Path(raw)


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _open_dir(path: Path, *, create: bool = False) -> int:
    """Open each component relative to its parent, never following symlinks."""
    path = _absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check_ancestors(path: Path) -> None:
    try:
        fd = _open_dir(path)
        os.close(fd)
    except OSError as exc:
        raise SafetyError(f"Directory is missing, unreadable, or has a symlink ancestor: {path}: {exc}") from exc


def _secure_stat(path: Path) -> os.stat_result:
    fd = _open_dir(path.parent)
    try:
        return os.stat(path.name, dir_fd=fd, follow_symlinks=False)
    finally:
        os.close(fd)


def _protect_output(path: Path, targets: list[Path]) -> None:
    _absolute(path)
    if any(_within(path, target) for target in targets):
        raise SafetyError(f"A report, plan, or journal cannot be inside a cleanup target: {path}")


def _check_existing_output_ancestors(path: Path) -> None:
    """Preflight a future output directory without creating it, including dry run."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in _absolute(path).parts[1:]:
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                return
            os.close(fd)
            fd = next_fd
        metadata = os.fstat(fd)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SafetyError(f"Existing output directory must be owned by you and mode 700: {path}")
    except OSError as exc:
        raise SafetyError(f"Output directory has an unreadable or symlink component: {path}: {exc}") from exc
    finally:
        os.close(fd)


def write_private(path: Path, value: Any, *, targets: list[Path] | None = None, replace: bool = False, text: bool = False) -> None:
    """Private, atomic output with fd-anchored parents and no symlink following."""
    path = _absolute(path)
    _protect_output(path, targets or [])
    fd = _open_dir(path.parent, create=True)
    temporary = ".cleanup-" + secrets.token_hex(16)
    temp_fd: int | None = None
    try:
        # New output directories are private. Require an existing output directory
        # to be user-owned and private too, instead of chmod'ing arbitrary parents.
        parent_stat = os.fstat(fd)
        if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
            raise SafetyError(f"Output directory must be owned by you and mode 700: {path.parent}")
        try:
            old = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None:
            if not replace or not stat.S_ISREG(old.st_mode) or old.st_uid != os.getuid():
                raise SafetyError(f"Output already exists or is not a regular user-owned file: {path}")
        temp_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        payload = value.encode("utf-8") if text else (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
        with os.fdopen(temp_fd, "wb") as stream:
            temp_fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            # Hard-linking the new inode publishes it without clobbering a file
            # another process created after our check. The temp link is removed.
            os.link(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=fd)
        os.fsync(fd)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def read_document(path: Path) -> dict[str, Any]:
    path = _absolute(path)
    fd = _open_dir(path.parent)
    try:
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANIFEST_BYTES:
                raise SafetyError("Manifest must be a regular file of at most 8 MiB.")
            value = json.loads(stream.read(MAX_MANIFEST_BYTES + 1))
    except (OSError, ValueError) as exc:
        raise SafetyError(f"Cannot safely read manifest: {path}: {exc}") from exc
    finally:
        os.close(fd)
    if not isinstance(value, dict):
        raise SafetyError("Manifest must contain a JSON object.")
    return value


def _check_binding(document: dict[str, Any], ctx: _Context, kind: str) -> None:
    if document.get("schema") != VERSION or document.get("kind") != kind:
        raise SafetyError(f"Unsupported {kind} schema.")
    if document.get("binding") != ctx.binding:
        raise SafetyError("Manifest belongs to another machine, user, or home directory.")
    if os.getuid() != ctx.uid or os.geteuid() != ctx.uid or ctx.uid == 0:
        raise SafetyError("User identity changed or root execution was requested.")


def _candidate_category(path: Path, ctx: _Context) -> str:
    path = _absolute(path)
    if not _within(path, ctx.home) or path == ctx.home:
        raise SafetyError(f"Path is outside the narrow cleanup allowlist: {path}")
    relative = path.relative_to(ctx.home)
    if any(name in relative.name.lower() for name in ("codex", "deepseek", "dsh")):
        raise SafetyError(f"Agent runtime/model/cache directories are deferred for manual review: {path}")
    for category, base in DIRECT_GROUPS:
        if relative.parent == Path(base) and relative.name not in ("", ".", ".."):
            return category
    for category, exact in EXACT_GROUPS:
        if relative == Path(exact):
            return category
    raise SafetyError(f"Path is outside the narrow cleanup allowlist: {path}")


def _candidate_id(path: Path, category: str, ctx: _Context) -> str:
    return "c-" + _digest({"binding": ctx.binding, "path": str(path), "category": category})[:16]


def _validate_candidate(item: dict[str, Any], ctx: _Context) -> Path:
    if not isinstance(item, dict) or not isinstance(item.get("path"), str):
        raise SafetyError("Malformed candidate.")
    path = _absolute(item["path"])
    category = _candidate_category(path, ctx)
    if item.get("category") != category or item.get("id") != _candidate_id(path, category, ctx):
        raise SafetyError(f"Candidate identity/category mismatch: {path}")
    try:
        metadata = _secure_stat(path)
    except OSError as exc:
        raise SafetyError(f"Target or ancestors are missing/unreadable: {path}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != ctx.uid:
        raise SafetyError(f"Target must be a real directory owned by the current user: {path}")
    return path


def _measurement(path: Path, deadline: float) -> dict[str, Any]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"status": "not_measured", "allocated_bytes": None, "reason": "Total scan time limit reached."}
    try:
        metadata = _secure_stat(path)
        if not stat.S_ISDIR(metadata.st_mode):
            return {"status": "excluded", "allocated_bytes": None, "reason": "Symlink or non-directory root; not followed."}
        # BSD du -k -x -s reports allocated KiB on one filesystem. It does not
        # follow interior symlinks. Absolute paths cannot be interpreted as flags.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(["/usr/bin/du", "-kxs", str(path)], stdout=stdout, stderr=stderr, timeout=min(MAX_DU_SECONDS, remaining), check=False)
            stdout.seek(0)
            stderr.seek(0)
            output = stdout.read(8192).decode("utf-8", "replace")
            errors = stderr.read(8192).decode("utf-8", "replace").strip()
        if completed.returncode != 0:
            return {"status": "error", "allocated_bytes": None, "reason": errors or f"du exited {completed.returncode}; size may be incomplete."}
        amount = int(output.split()[0]) * 1024
        return {"status": "measured", "allocated_bytes": amount}
    except FileNotFoundError:
        return {"status": "missing", "allocated_bytes": None}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "allocated_bytes": None, "reason": "du time limit reached; no size is claimed."}
    except (OSError, ValueError, IndexError, SafetyError) as exc:
        return {"status": "error", "allocated_bytes": None, "reason": str(exc)}


def scan(ctx: _Context) -> dict[str, Any]:
    """Read bounded directory names, metadata, and allocated sizes only."""
    started = _now()
    deadline = time.monotonic() + MAX_SCAN_SECONDS
    issues: list[dict[str, str]] = []
    locations: list[tuple[str, Path]] = []
    deferred: list[dict[str, Any]] = []
    for category, base in DIRECT_GROUPS:
        root = ctx.home / base
        try:
            fd = _open_dir(root)
            try:
                children: list[str] = []
                with os.scandir(fd) as entries:
                    for index, entry in enumerate(entries):
                        if index >= MAX_ENUMERATED_CHILDREN:
                            issues.append({"path": str(root), "reason": f"Direct-child enumeration stopped after {MAX_ENUMERATED_CHILDREN} entries; inventory is partial."})
                            break
                        if time.monotonic() >= deadline:
                            issues.append({"path": str(root), "reason": "Total scan time limit reached during enumeration."})
                            break
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if any(name in entry.name.lower() for name in ("codex", "deepseek", "dsh")):
                                    deferred.append({"label": "Agent cache — deferred", "path": str(root / entry.name), "apply_allowed": False, "reason": "Codex/DeepSeek/DSH runtime or agent cache excluded from executable candidates."})
                                else:
                                    children.append(entry.name)
                            elif entry.is_symlink():
                                issues.append({"path": str(root / entry.name), "reason": "Symlink root excluded; not followed."})
                        except OSError as exc:
                            issues.append({"path": str(root / entry.name), "reason": str(exc)})
                locations.extend((category, root / name) for name in sorted(children))
            finally:
                os.close(fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            issues.append({"path": str(root), "reason": f"Missing access or a symlink ancestor; not traversed: {exc}"})
    for category, exact in EXACT_GROUPS:
        root = ctx.home / exact
        try:
            metadata = _secure_stat(root)
            if stat.S_ISDIR(metadata.st_mode):
                locations.append((category, root))
            else:
                issues.append({"path": str(root), "reason": "Symlink or non-directory cache root excluded."})
        except FileNotFoundError:
            continue
        except (OSError, SafetyError) as exc:
            issues.append({"path": str(root), "reason": str(exc)})
    # Exact package caches are few; measure them first so a large number of app
    # directories does not prevent their inclusion in this bounded inventory.
    exact_names = {category for category, _ in EXACT_GROUPS}
    locations.sort(key=lambda pair: (pair[0] not in exact_names, str(pair[1])))
    if len(locations) > MAX_CANDIDATES:
        issues.append({"path": str(ctx.home), "reason": f"Candidate limit {MAX_CANDIDATES} reached; {len(locations) - MAX_CANDIDATES} discovered cache directories omitted."})
        locations = locations[:MAX_CANDIDATES]
    candidates = []
    for category, path in locations:
        candidates.append({"id": _candidate_id(path, category, ctx), "path": str(path), "category": category, "consequences": CONSEQUENCES[category], "review_required": True, **_measurement(path, deadline)})
    overview = []
    for item in deferred:
        overview.append({**item, **_measurement(Path(item["path"]), deadline)})
    for label, relative in DEFERRED_REVIEW_LOCATIONS + REVIEW_LOCATIONS:
        path = ctx.home / relative
        overview.append({"label": label, "path": str(path), "apply_allowed": False, **_measurement(path, deadline)})
    usage = shutil.disk_usage(ctx.home)
    return _seal({"schema": VERSION, "kind": "scan", "binding": ctx.binding, "created_at": _stamp(started), "completed_at": _stamp(), "scan_limits": {"seconds": MAX_SCAN_SECONDS, "du_seconds_per_path": MAX_DU_SECONDS, "children_per_root": MAX_ENUMERATED_CHILDREN, "candidates": MAX_CANDIDATES, "cross_filesystem": False, "symlinks_followed": False}, "disk": {"total_bytes": usage.total, "free_bytes": usage.free}, "candidates": candidates, "review_only": overview, "issues": issues, "size_note": "du allocated bytes are estimates. APFS clones, compression, snapshots and links mean summed allocated sizes are not a promise of recoverable free space. Missing/denied/timed-out locations are not counted as zero."})


def _record(metadata: os.stat_result) -> list[int]:
    return [metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink, getattr(metadata, "st_flags", 0), getattr(metadata, "st_blocks", 0)]


def fingerprint(path: Path, ctx: _Context) -> dict[str, Any]:
    """Hash a complete bounded tree of no-follow metadata, never file contents."""
    start = time.monotonic()
    parent_fd = _open_dir(path.parent)
    root_fd: int | None = None
    count = 0
    allocated = 0
    hardlinked_files = 0
    hasher = hashlib.sha256()
    try:
        initial = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(initial.st_mode) or initial.st_uid != ctx.uid:
            raise SafetyError(f"Target is not a real user-owned directory: {path}")
        if initial.st_dev != os.fstat(parent_fd).st_dev:
            raise SafetyError(f"Target is a filesystem mount root; automatic cleanup refused: {path}")
        root_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        if _record(os.fstat(root_fd)) != _record(initial):
            raise SafetyError(f"Target changed while opening: {path}")
        device = initial.st_dev

        def visit(fd: int, relative: str, metadata: os.stat_result, depth: int) -> None:
            nonlocal count, allocated, hardlinked_files
            if depth > MAX_TREE_DEPTH:
                raise SafetyError(f"Tree exceeds maximum depth {MAX_TREE_DEPTH}: {path}")
            if metadata.st_dev != device:
                raise SafetyError(f"Tree crosses a mount boundary: {path / relative}")
            if metadata.st_uid != ctx.uid:
                raise SafetyError(f"Tree contains an entry owned by another user; no permission bypass: {path / relative}")
            count += 1
            allocated += getattr(metadata, "st_blocks", 0) * 512
            if count > MAX_TREE_ENTRIES or time.monotonic() - start > MAX_TREE_SECONDS:
                raise SafetyError(f"Tree exceeds bounded fingerprint limits ({MAX_TREE_ENTRIES} entries / {MAX_TREE_SECONDS}s): {path}")
            hasher.update(_canonical([relative, _record(metadata)]))
            hasher.update(b"\n")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink > 1:
                hardlinked_files += 1
            if not stat.S_ISDIR(metadata.st_mode):
                if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
                    raise SafetyError(f"Special file encountered; automatic cleanup refused: {path / relative}")
                if stat.S_ISREG(metadata.st_mode) and not metadata.st_mode & 0o400:
                    raise SafetyError(f"Unreadable file; permissions will not be changed: {path / relative}")
                return
            if not metadata.st_mode & 0o400 or not metadata.st_mode & 0o100:
                raise SafetyError(f"Unreadable/unsearchable directory; permissions will not be changed: {path / relative}")
            with os.scandir(fd) as entries:
                names: list[str] = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) + count > MAX_TREE_ENTRIES or time.monotonic() - start > MAX_TREE_SECONDS:
                        raise SafetyError(f"Directory exceeds bounded fingerprint limits: {path / relative}")
            for name in sorted(names):
                item = os.stat(name, dir_fd=fd, follow_symlinks=False)
                child = f"{relative}/{name}" if relative else name
                if stat.S_ISDIR(item.st_mode):
                    child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if _record(os.fstat(child_fd)) != _record(item):
                            raise SafetyError(f"Directory changed while opening: {path / child}")
                        visit(child_fd, child, item, depth + 1)
                    finally:
                        os.close(child_fd)
                else:
                    visit(fd, child, item, depth + 1)
            if _record(os.fstat(fd)) != _record(metadata):
                raise SafetyError(f"Directory changed during fingerprinting: {path / relative}")

        visit(root_fd, "", initial, 0)
        if _record(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) != _record(initial):
            raise SafetyError(f"Target changed during fingerprinting: {path}")
        return {"sha256": hasher.hexdigest(), "entries": count, "root_metadata": _record(initial), "metadata_allocated_bytes": allocated, "hardlinked_files": hardlinked_files}
    except OSError as exc:
        raise SafetyError(f"Cannot completely fingerprint target; no permission bypass: {path}: {exc}") from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


def _no_overlaps(paths: list[Path]) -> None:
    for index, path in enumerate(paths):
        for other in paths[index + 1:]:
            if _within(path, other) or _within(other, path):
                raise SafetyError("Cleanup targets overlap or are repeated.")


def make_plan(manifest: dict[str, Any], ids: list[str], method: str, ctx: _Context, *, scan_path: Path, out_path: Path) -> dict[str, Any]:
    _verify_seal(manifest)
    _check_binding(manifest, ctx, "scan")
    _fresh(manifest.get("created_at"), "Scan")
    if method not in ("trash", "delete"):
        raise SafetyError("Cleanup method must be trash or delete.")
    if not ids or len(ids) != len(set(ids)) or len(ids) > MAX_PLAN_TARGETS:
        raise SafetyError(f"Select 1–{MAX_PLAN_TARGETS} distinct, exact candidate IDs from the scan.")
    available = manifest.get("candidates")
    if not isinstance(available, list) or len(available) > MAX_CANDIDATES:
        raise SafetyError("Invalid candidate inventory.")
    indexed: dict[str, dict[str, Any]] = {}
    for candidate in available:
        if not isinstance(candidate, dict) or not isinstance(candidate.get("id"), str) or candidate["id"] in indexed:
            raise SafetyError("Malformed or duplicate candidate identity.")
        indexed[candidate["id"]] = candidate
    selected = []
    paths = []
    fingerprint_started = time.monotonic()
    fingerprint_entries = 0
    for candidate_id in ids:
        if candidate_id not in indexed:
            raise SafetyError(f"ID is absent from the scan: {candidate_id}")
        candidate = indexed[candidate_id]
        path = _validate_candidate(candidate, ctx)
        if candidate.get("status") != "measured" or not isinstance(candidate.get("allocated_bytes"), int) or candidate["allocated_bytes"] < 0:
            raise SafetyError(f"Selected candidate was not successfully measured: {path}")
        paths.append(path)
        selected.append({"id": candidate_id, "path": str(path), "category": candidate["category"], "scan_allocated_bytes": candidate["allocated_bytes"], "consequences": CONSEQUENCES[candidate["category"]], "fingerprint": fingerprint(path, ctx)})
        fingerprint_entries += selected[-1]["fingerprint"]["entries"]
        if fingerprint_entries > MAX_PLAN_ENTRIES or time.monotonic() - fingerprint_started > MAX_PLAN_SECONDS:
            raise SafetyError("Selected targets exceed total planning bounds; select a smaller batch.")
    _no_overlaps(paths)
    _protect_output(_absolute(scan_path), paths)
    _protect_output(_absolute(out_path), paths)
    return _seal({"schema": VERSION, "kind": "plan", "binding": ctx.binding, "created_at": _stamp(), "scan_created_at": manifest["created_at"], "scan_digest": manifest["digest"], "scan_path": str(scan_path), "plan_path": str(out_path), "method": method, "targets": selected, "estimated_allocated_bytes": sum(item["scan_allocated_bytes"] for item in selected), "method_consequence": "Moves directories into your Trash on the same filesystem. This normally releases no disk space now. Trash is never emptied. To restore, manually move each recorded destination back to its recorded original path after resolving conflicts; Finder Put Back is not guaranteed." if method == "trash" else "Permanently deletes these exact directories without using Trash. This helper cannot restore them. Released disk space can be less than the allocated-byte estimate.", "required_before_apply": ["Review every exact path and consequence with the user and obtain explicit approval for this exact method and plan.", "Quit owning apps, IDEs, builds and package-manager operations to stop concurrent writes.", "Run apply without --execute first. Any changed target requires a new scan and plan."], "authorization_note": "The digest detects changes; knowing it is not user authorization. The assistant must obtain explicit human confirmation separately."})


def _validate_plan(plan: dict[str, Any], ctx: _Context, plan_path: Path, journal_dir: Path) -> list[Path]:
    _verify_seal(plan)
    _check_binding(plan, ctx, "plan")
    _fresh(plan.get("created_at"), "Plan")
    _fresh(plan.get("scan_created_at"), "Source scan")
    if plan.get("method") not in ("trash", "delete"):
        raise SafetyError("Invalid cleanup method.")
    if plan.get("plan_path") != str(plan_path):
        raise SafetyError("Plan was moved; create a new plan at its intended output path.")
    targets = plan.get("targets")
    if not isinstance(targets, list) or not targets or len(targets) > MAX_PLAN_TARGETS:
        raise SafetyError("Invalid target list.")
    paths = [_validate_candidate(target, ctx) for target in targets]
    _no_overlaps(paths)
    for output in (plan_path, _absolute(plan.get("scan_path", "")), journal_dir):
        _protect_output(output, paths)
    _check_existing_output_ancestors(journal_dir)
    # Validate every target before creating a Trash directory or journal and
    # before mutating even the first target.
    fingerprint_started = time.monotonic()
    fingerprint_entries = 0
    for target, path in zip(targets, paths):
        current = fingerprint(path, ctx)
        fingerprint_entries += current["entries"]
        if fingerprint_entries > MAX_PLAN_ENTRIES or time.monotonic() - fingerprint_started > MAX_PLAN_SECONDS:
            raise SafetyError("Selected targets exceed total validation bounds; select a smaller batch.")
        if current != target.get("fingerprint"):
            raise SafetyError(f"Target changed since planning; nothing has been cleaned: {path}")
    return paths


def _rename_noreplace(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
    """Atomic no-clobber rename. macOS production; Linux branch is for fixtures."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flag = 0x00000004  # Darwin RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function = getattr(libc, "renameat2", None)
        flag = 1  # Linux RENAME_NOREPLACE; public CLI still refuses Linux.
    else:
        function = None
        flag = 0
    if function is None:
        raise SafetyError("Atomic no-overwrite rename is unavailable; no fallback copy is allowed.")
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), flag) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _trash_fd(ctx: _Context, *, create: bool) -> int:
    home_fd = _open_dir(ctx.home)
    try:
        if create:
            try:
                os.mkdir(".Trash", 0o700, dir_fd=home_fd)
            except FileExistsError:
                pass
        fd = os.open(".Trash", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        metadata = os.fstat(fd)
        if metadata.st_uid != ctx.uid or stat.S_IMODE(metadata.st_mode) & 0o077:
            os.close(fd)
            raise SafetyError("Trash must be a real private directory owned by you; permissions will not be changed.")
        return fd
    finally:
        os.close(home_fd)


def apply_plan(plan: dict[str, Any], ctx: _Context, *, plan_path: Path, journal_dir: Path, execute: bool = False, confirm: str | None = None) -> dict[str, Any]:
    paths = _validate_plan(plan, ctx, plan_path, journal_dir)
    if execute and (not isinstance(confirm, str) or not hmac.compare_digest(confirm, plan["digest"])):
        raise SafetyError("Execution requires --execute and --confirm with this exact full plan digest, after explicit human approval.")
    if plan["method"] == "delete" and (not getattr(shutil.rmtree, "avoids_symlink_attacks", False) or "dir_fd" not in inspect.signature(shutil.rmtree).parameters):
        raise SafetyError("Permanent deletion requires Python 3.11+ with fd-based symlink-resistant shutil.rmtree(dir_fd=...). Use a supported interpreter or choose Trash; no unsafe fallback is allowed.")
    trash_fd: int | None = None
    try:
        # A missing Trash is acceptable for dry run. Existing Trash must be safe.
        if plan["method"] == "trash":
            try:
                trash_fd = _trash_fd(ctx, create=False)
                trash_device = os.fstat(trash_fd).st_dev
            except FileNotFoundError:
                home_fd = _open_dir(ctx.home)
                try:
                    trash_device = os.fstat(home_fd).st_dev
                finally:
                    os.close(home_fd)
            for path in paths:
                if _secure_stat(path).st_dev != trash_device:
                    raise SafetyError(f"Trash move would cross filesystems; no copy fallback is allowed: {path}")
        free_before = shutil.disk_usage(ctx.home).free
        summary = {"schema": VERSION, "kind": "apply-result", "binding": ctx.binding, "plan_digest": plan["digest"], "method": plan["method"], "dry_run": not execute, "created_at": _stamp(), "estimated_allocated_bytes": plan["estimated_allocated_bytes"], "free_bytes_before": free_before, "operations": [], "note": plan["method_consequence"]}
        if not execute:
            summary["operations"] = [{"original": str(path), "state": "would_move_to_trash" if plan["method"] == "trash" else "would_permanently_delete"} for path in paths]
            summary["free_bytes_after"] = None
            summary["observed_free_bytes_delta"] = None
            summary["space_note"] = "Dry run: no cleanup occurred and no post-cleanup free-space measurement was taken."
            return summary
        # Create an immutable initial journal before target mutation. A private
        # output error aborts here. Updates are fsync'd after every operation.
        journal_path = journal_dir / ("cleanup-" + _now().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(8) + ".json")
        _protect_output(journal_path, paths)
        summary["journal_path"] = str(journal_path)
        summary["state"] = "prepared"
        write_private(journal_path, summary, targets=paths)
        if plan["method"] == "trash" and trash_fd is None:
            trash_fd = _trash_fd(ctx, create=True)
        for target, path in zip(plan["targets"], paths):
            operation: dict[str, Any] = {"original": str(path), "state": "pending"}
            parent_fd: int | None = None
            try:
                # Repeat immediately before this operation. Apps can write after
                # initial validation; a later failure is journaled as partial.
                if fingerprint(path, ctx) != target["fingerprint"]:
                    raise SafetyError(f"Target changed during apply: {path}")
                parent_fd = _open_dir(path.parent)
                if _record(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) != target["fingerprint"]["root_metadata"]:
                    raise SafetyError(f"Target identity changed before mutation: {path}")
                if plan["method"] == "trash":
                    assert trash_fd is not None
                    destination = path.name + ".codex-cleanup-" + secrets.token_hex(12)
                    operation["destination"] = str(ctx.home / ".Trash" / destination)
                summary["operations"].append(operation)
                summary["state"] = "in_progress"
                write_private(journal_path, summary, targets=paths, replace=True)
                if plan["method"] == "trash":
                    if os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False).st_dev != os.fstat(trash_fd).st_dev:
                        raise SafetyError("Filesystem changed; Trash copy fallback is forbidden.")
                    _rename_noreplace(parent_fd, path.name, trash_fd, destination)
                    destination_metadata = os.stat(destination, dir_fd=trash_fd, follow_symlinks=False)
                    expected_root = target["fingerprint"]["root_metadata"]
                    if (destination_metadata.st_dev, destination_metadata.st_ino) != tuple(expected_root[:2]):
                        operation["state"] = "moved_identity_mismatch"
                        raise SafetyError("A concurrent rename changed target identity; inspect the recorded Trash destination before restoration.")
                    operation["state"] = "moved_to_trash"
                    os.fsync(trash_fd)
                else:
                    shutil.rmtree(path.name, dir_fd=parent_fd)
                    operation["state"] = "permanently_deleted"
                os.fsync(parent_fd)
                try:
                    os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                    operation["original_path_absent"] = False
                    operation["verification_note"] = "Original path exists after cleanup, possibly recreated by an app. Do not delete it automatically."
                except FileNotFoundError:
                    operation["original_path_absent"] = True
                write_private(journal_path, summary, targets=paths, replace=True)
            except BaseException as exc:
                if operation not in summary["operations"]:
                    summary["operations"].append(operation)
                operation["error"] = str(exc)
                if operation["state"] == "pending":
                    operation["state"] = "failed_or_partial"
                summary["state"] = "aborted"
                summary["free_bytes_after"] = shutil.disk_usage(ctx.home).free
                summary["observed_free_bytes_delta"] = summary["free_bytes_after"] - free_before
                try:
                    write_private(journal_path, summary, targets=paths, replace=True)
                except BaseException as journal_exc:
                    raise SafetyError(f"Cleanup aborted: {exc}. Journal update also failed: {journal_exc}. Preserve {journal_path} and inspect recorded pending operations manually.") from exc
                raise SafetyError(f"Cleanup aborted: {exc}. Earlier operations may have completed; inspect {journal_path}.") from exc
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)
        summary["state"] = "completed"
        summary["completed_at"] = _stamp()
        summary["free_bytes_after"] = shutil.disk_usage(ctx.home).free
        summary["observed_free_bytes_delta"] = summary["free_bytes_after"] - free_before
        summary["space_note"] = "Observed free-space change includes concurrent system activity. Trash moves usually release no space. APFS clones, hard links and snapshots can reduce or delay space recovery; allocated bytes are not reclaimed bytes."
        write_private(journal_path, summary, targets=paths, replace=True)
        return summary
    finally:
        if trash_fd is not None:
            os.close(trash_fd)


def _size(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "unknown"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(amount) < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "unknown"


def _md(value: Any) -> str:
    # Paths can contain Markdown delimiters and newlines. JSON escaping prevents
    # a filename from creating fake rows or instructions in a report.
    return json.dumps(str(value), ensure_ascii=True)[1:-1].replace("|", "\\|").replace("`", "\\`").replace("<", "&lt;").replace(">", "&gt;")


def scan_markdown(document: dict[str, Any]) -> str:
    lines = ["# macOS cache scan", "", f"Scanned: {_md(document['completed_at'])}", f"Free space: {_size(document['disk']['free_bytes'])}", "", "Metadata-only bounded inventory. Every candidate requires app-specific review and explicit user approval. No cleanup has run.", "", "| Candidate ID | Allocated size | Category | Path | Status |", "| --- | ---: | --- | --- | --- |"]
    for item in sorted(document["candidates"], key=lambda item: -(item.get("allocated_bytes") or 0)):
        lines.append(f"| {_md(item['id'])} | {_size(item.get('allocated_bytes'))} | {_md(item['category'])} | {_md(item['path'])} | {_md(item['status'])} |")
    lines.extend(["", "## Consequences to review", ""])
    for category in sorted({item["category"] for item in document["candidates"]}):
        lines.append(f"- {category}: {CONSEQUENCES[category]}")
    lines.extend(["", "## Overview only — excluded from apply", "", "| Location | Allocated size | Path | Status |", "| --- | ---: | --- | --- |"])
    for item in document["review_only"]:
        lines.append(f"| {_md(item['label'])} | {_size(item.get('allocated_bytes'))} | {_md(item['path'])} | {_md(item['status'])} |")
    errors = document["issues"] + [{"path": item["path"], "reason": item["reason"]} for item in document["candidates"] + document["review_only"] if item.get("reason")]
    if errors:
        lines.extend(["", "## Limits and access errors", ""])
        lines.extend(f"- {_md(item['path'])}: {_md(item['reason'])}" for item in errors)
    lines.extend(["", document["size_note"], "", "Moving to Trash normally releases no disk space until a person separately empties it. This helper never empties Trash.", ""])
    return "\n".join(lines)


def plan_markdown(plan: dict[str, Any]) -> str:
    lines = ["# Cleanup plan — awaiting explicit approval", "", f"Method: **{plan['method']}**", f"Estimated allocated bytes selected: {_size(plan['estimated_allocated_bytes'])}", "", plan["method_consequence"], "", "| Candidate ID | Allocated size at scan | Exact target | Consequence |", "| --- | ---: | --- | --- |"]
    for target in plan["targets"]:
        lines.append(f"| {_md(target['id'])} | {_size(target['scan_allocated_bytes'])} | {_md(target['path'])} | {_md(target['consequences'])} |")
    lines.extend(["", "Before execution:", ""] + [f"- {item}" for item in plan["required_before_apply"]])
    lines.extend(["", f"Full plan digest: `{plan['digest']}`", "", plan["authorization_note"], ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    scanner = commands.add_parser("scan", help="Read bounded metadata and allocated sizes; no target changes.")
    scanner.add_argument("--out-dir", required=True, help="New or private mode-700 report directory outside all cache targets.")
    planner = commands.add_parser("plan", help="Prepare an exact reviewable plan from selected candidate IDs.")
    planner.add_argument("--scan", required=True)
    planner.add_argument("--ids", required=True, help="Comma-separated exact IDs from scan.json.")
    planner.add_argument("--method", choices=("trash", "delete"), default="trash")
    planner.add_argument("--out", required=True, help="New plan JSON path; a Markdown sibling is written too.")
    applier = commands.add_parser("apply", help="Validate and dry-run by default. Execute only after human approval.")
    applier.add_argument("--plan", required=True)
    applier.add_argument("--journal-dir", help="Private journal directory; defaults to a journals sibling of the plan.")
    applier.add_argument("--execute", action="store_true")
    applier.add_argument("--confirm", help="Full exact plan digest, after separate explicit human approval.")
    args = parser.parse_args(argv)
    try:
        ctx = current_context()
        if args.command == "scan":
            out_dir = _absolute(os.path.abspath(os.path.expanduser(args.out_dir)))
            # Protect both discovered and potential allowlisted roots so creating
            # the report itself cannot alter an unselected cache tree.
            for _, base in DIRECT_GROUPS + EXACT_GROUPS:
                if _within(out_dir, ctx.home / base):
                    raise SafetyError("Reports must be outside all cache locations.")
            document = scan(ctx)
            paths = [Path(item["path"]) for item in document["candidates"]]
            write_private(out_dir / "scan.json", document, targets=paths)
            write_private(out_dir / "scan.md", scan_markdown(document), targets=paths, text=True)
            print(json.dumps({"scan": str(out_dir / "scan.json"), "report": str(out_dir / "scan.md"), "candidates": len(document["candidates"]), "issues": len(document["issues"]), "digest": document["digest"]}))
        elif args.command == "plan":
            scan_path = _absolute(os.path.abspath(os.path.expanduser(args.scan)))
            out_path = _absolute(os.path.abspath(os.path.expanduser(args.out)))
            if out_path.suffix.lower() != ".json":
                raise SafetyError("Plan output must end in .json.")
            plan = make_plan(read_document(scan_path), [item.strip() for item in args.ids.split(",")], args.method, ctx, scan_path=scan_path, out_path=out_path)
            paths = [Path(item["path"]) for item in plan["targets"]]
            write_private(out_path, plan, targets=paths)
            write_private(out_path.with_suffix(".md"), plan_markdown(plan), targets=paths, text=True)
            print(json.dumps({"plan": str(out_path), "review": str(out_path.with_suffix(".md")), "method": plan["method"], "digest": plan["digest"], "execution": "Not executed. Obtain explicit human approval, then validate with apply dry run."}))
        else:
            plan_path = _absolute(os.path.abspath(os.path.expanduser(args.plan)))
            journal_dir = _absolute(os.path.abspath(os.path.expanduser(args.journal_dir))) if args.journal_dir else plan_path.parent / "journals"
            result = apply_plan(read_document(plan_path), ctx, plan_path=plan_path, journal_dir=journal_dir, execute=args.execute, confirm=args.confirm)
            print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (SafetyError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Refused/failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. If execution had started, inspect the journal before doing anything else.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
