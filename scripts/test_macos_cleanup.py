"""Safety tests. Every target and all mutations are in private temp fixtures."""

from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import inspect
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).absolute().parent
SCRIPT = HERE / "macos_cleanup.py"
SPEC = importlib.util.spec_from_file_location("macos_cleanup_fixture_module", SCRIPT)
helper = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = helper
SPEC.loader.exec_module(helper)
CAN_DELETE = getattr(shutil.rmtree, "avoids_symlink_attacks", False) and "dir_fd" in inspect.signature(shutil.rmtree).parameters


class CleanupSafetyTests(unittest.TestCase):
    def setUp(self):
        # Keep fixtures in the caller's work directory, outside installed skills.
        fixture_root = Path.cwd() / "work" / "macos-cleanup-tests"
        fixture_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="fixture-", dir=fixture_root.resolve())
        self.base = Path(self.temporary.name)
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.ctx = helper._Context(home=self.home, uid=os.getuid(), host="fixture-host")
        self.artifacts = self.base / "reports"
        self.artifacts.mkdir(mode=0o700)
        self.target = self.home / "Library/Caches/com.example.fixture"
        self.target.mkdir(mode=0o700, parents=True)
        (self.target / "payload").write_bytes(b"fixture cache only")
        self.scan_path = self.artifacts / "scan.json"
        self.plan_path = self.artifacts / "plan.json"
        self.journals = self.artifacts / "journals"

    def tearDown(self):
        self.temporary.cleanup()

    def candidate(self, path=None, category="app-cache"):
        path = path or self.target
        return {"id": helper._candidate_id(path, category, self.ctx), "path": str(path), "category": category, "status": "measured", "allocated_bytes": 4096}

    def manifest(self, candidates=None):
        return helper._seal({"schema": helper.VERSION, "kind": "scan", "binding": self.ctx.binding, "created_at": helper._stamp(), "candidates": candidates or [self.candidate()]})

    def plan(self, method="trash", candidates=None):
        manifest = self.manifest(candidates)
        return helper.make_plan(manifest, [item["id"] for item in manifest["candidates"]], method, self.ctx, scan_path=self.scan_path, out_path=self.plan_path)

    def apply(self, plan, **kwargs):
        return helper.apply_plan(plan, self.ctx, plan_path=self.plan_path, journal_dir=self.journals, **kwargs)

    def test_true_dry_run_does_not_create_trash_or_journal_or_mutate_target(self):
        plan = self.plan()
        before = helper.fingerprint(self.target, self.ctx)
        result = self.apply(plan)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["operations"][0]["state"], "would_move_to_trash")
        self.assertFalse((self.home / ".Trash").exists())
        self.assertFalse(self.journals.exists())
        self.assertEqual(before, helper.fingerprint(self.target, self.ctx))

    def test_exact_consent_required_and_wrong_tokens_never_mutate(self):
        plan = self.plan()
        for confirmation in (None, "", plan["digest"][:12], plan["digest"] + " ", "yes"):
            with self.subTest(confirmation=confirmation), self.assertRaises(helper.SafetyError):
                self.apply(plan, execute=True, confirm=confirmation)
            self.assertTrue(self.target.exists())
            self.assertFalse(self.journals.exists())
            self.assertFalse((self.home / ".Trash").exists())

    def test_digest_without_execute_is_still_dry_run(self):
        plan = self.plan()
        result = self.apply(plan, confirm=plan["digest"])
        self.assertTrue(result["dry_run"])
        self.assertTrue(self.target.exists())
        self.assertFalse(self.journals.exists())

    def test_all_targets_revalidated_before_first_mutation(self):
        second = self.home / "Library/Caches/com.example.second"
        second.mkdir()
        (second / "file").write_text("before")
        plan = self.plan(candidates=[self.candidate(), self.candidate(second)])
        (second / "file").write_text("changed after planning")
        with self.assertRaisesRegex(helper.SafetyError, "changed since planning"):
            self.apply(plan, execute=True, confirm=plan["digest"])
        self.assertTrue(self.target.exists())
        self.assertTrue(second.exists())
        self.assertFalse(self.journals.exists())
        self.assertFalse((self.home / ".Trash").exists())

    def test_symlink_target_is_not_planable(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        shutil.rmtree(self.target)
        self.target.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(helper.SafetyError):
            self.plan()
        self.assertEqual((outside / "keep").read_text(), "keep")

    def test_symlink_ancestor_is_not_planable(self):
        caches = self.target.parent
        outside = self.base / "outside"
        outside.mkdir()
        (outside / self.target.name).mkdir()
        shutil.rmtree(caches)
        caches.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((helper.SafetyError, OSError)):
            self.plan()
        self.assertTrue((outside / self.target.name).exists())

    def test_symlink_substitution_after_plan_is_rejected(self):
        plan = self.plan()
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        shutil.rmtree(self.target)
        self.target.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(helper.SafetyError):
            self.apply(plan, execute=True, confirm=plan["digest"])
        self.assertTrue((outside / "keep").exists())
        self.assertFalse(self.journals.exists())

    def test_forbidden_roots_and_forged_manifest_are_rejected(self):
        forbidden = [self.home, self.home / "Documents", Path("/System"), self.home / "Library/Caches", self.home / "Library/Developer/Xcode/DerivedData", self.home / ".codex", self.home / ".dsh", self.home / ".agents", self.home / "Downloads", self.home / ".Trash", self.home / "Library/Logs", self.home / "Library/Application Support"]
        for path in forbidden:
            with self.subTest(path=path), self.assertRaises(helper.SafetyError):
                candidate = self.candidate(path)
                forged = self.manifest([candidate])  # Deliberately re-sealed forgery.
                helper.make_plan(forged, [candidate["id"]], "trash", self.ctx, scan_path=self.scan_path, out_path=self.plan_path)
        self.assertTrue(self.target.exists())

    def test_agent_cache_names_are_deferred_even_in_allowlisted_parent(self):
        for name in ("Codex", "com.openai.codex", "deepseek-harness", "dsh-cache"):
            path = self.target.parent / name
            path.mkdir()
            with self.subTest(name=name), self.assertRaises(helper.SafetyError):
                self.plan(candidates=[self.candidate(path)])
            self.assertTrue(path.exists())

    def test_tampered_plan_digest_rejected(self):
        plan = self.plan()
        plan["method"] = "delete"
        with self.assertRaisesRegex(helper.SafetyError, "digest mismatch"):
            self.apply(plan, execute=True, confirm=plan["digest"])
        self.assertTrue(self.target.exists())
        self.assertFalse(self.journals.exists())

    def test_machine_binding_and_stale_scan_rejected(self):
        manifest = self.manifest()
        payload = {k: v for k, v in manifest.items() if k != "digest"}
        for altered in (
            {**payload, "binding": {**self.ctx.binding, "host": "other-mac"}},
            {**payload, "created_at": helper._stamp(helper._now() - dt.timedelta(hours=25))},
        ):
            with self.assertRaises(helper.SafetyError):
                helper.make_plan(helper._seal(altered), [self.candidate()["id"]], "trash", self.ctx, scan_path=self.scan_path, out_path=self.plan_path)

    def test_stale_plan_rejected(self):
        plan = self.plan()
        payload = {k: v for k, v in plan.items() if k != "digest"}
        payload["created_at"] = helper._stamp(helper._now() - dt.timedelta(hours=25))
        stale = helper._seal(payload)
        with self.assertRaises(helper.SafetyError):
            self.apply(stale, execute=True, confirm=stale["digest"])
        self.assertTrue(self.target.exists())

    def test_output_and_journal_inside_target_rejected(self):
        manifest = self.manifest()
        with self.assertRaises(helper.SafetyError):
            helper.make_plan(manifest, [self.candidate()["id"]], "trash", self.ctx, scan_path=self.scan_path, out_path=self.target / "plan.json")
        plan = self.plan()
        with self.assertRaises(helper.SafetyError):
            helper.apply_plan(plan, self.ctx, plan_path=self.plan_path, journal_dir=self.target / "journal", execute=True, confirm=plan["digest"])
        self.assertTrue(self.target.exists())

    def test_private_outputs_and_symlink_output_parent(self):
        output = self.artifacts / "new" / "scan.json"
        helper.write_private(output, {"fixture": True})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o700)
        link = self.base / "symlink-output"
        link.symlink_to(self.artifacts, target_is_directory=True)
        with self.assertRaises(OSError):
            helper.write_private(link / "forbidden.json", {})
        self.assertFalse((self.artifacts / "forbidden.json").exists())

    def test_dry_run_rejects_symlink_journal_without_mutation(self):
        plan = self.plan()
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        self.journals.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(helper.SafetyError):
            self.apply(plan)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(self.target.exists())
        self.assertFalse((self.home / ".Trash").exists())

    def test_existing_output_does_not_get_overwritten(self):
        path = self.artifacts / "existing.json"
        path.write_text("keep")
        with self.assertRaises(helper.SafetyError):
            helper.write_private(path, {"changed": True})
        self.assertEqual(path.read_text(), "keep")

    def test_unreadable_tree_refused_without_chmod(self):
        unreadable = self.target / "unreadable"
        unreadable.mkdir()
        unreadable.chmod(0)
        try:
            with self.assertRaises(helper.SafetyError):
                self.plan()
            self.assertEqual(stat.S_IMODE(unreadable.stat().st_mode), 0)
        finally:
            unreadable.chmod(0o700)
        file = self.target / "payload"
        file.chmod(0)
        try:
            with self.assertRaises(helper.SafetyError):
                self.plan()
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0)
        finally:
            file.chmod(0o600)

    def test_entry_limit_refuses_without_mutation(self):
        with mock.patch.object(helper, "MAX_TREE_ENTRIES", 1):
            with self.assertRaises(helper.SafetyError):
                self.plan()
        self.assertTrue((self.target / "payload").exists())

    def test_successful_trash_move_and_manual_restore_mapping(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        (self.target / "link").symlink_to(outside, target_is_directory=True)
        plan = self.plan()
        result = self.apply(plan, execute=True, confirm=plan["digest"])
        self.assertEqual(result["state"], "completed")
        operation = result["operations"][0]
        self.assertEqual(operation["state"], "moved_to_trash")
        self.assertEqual(operation["original"], str(self.target))
        self.assertFalse(self.target.exists())
        destination = Path(operation["destination"])
        self.assertTrue(destination.is_dir())
        self.assertTrue((destination / "link").is_symlink())
        self.assertEqual((outside / "keep").read_text(), "keep")
        journal = helper.read_document(Path(result["journal_path"]))
        self.assertEqual(journal["operations"][0], operation)
        self.assertTrue(operation["original_path_absent"])
        self.assertIn("observed_free_bytes_delta", journal)

    @unittest.skipUnless(CAN_DELETE, "Permanent-delete fixtures require Python 3.11+ fd-based rmtree")
    def test_successful_permanent_delete_does_not_follow_interior_symlink(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        (self.target / "link").symlink_to(outside, target_is_directory=True)
        plan = self.plan(method="delete")
        result = self.apply(plan, execute=True, confirm=plan["digest"])
        self.assertEqual(result["operations"][0]["state"], "permanently_deleted")
        self.assertFalse(self.target.exists())
        self.assertFalse((self.home / ".Trash").exists())
        self.assertEqual((outside / "keep").read_text(), "keep")

    def test_older_rmtree_without_dir_fd_has_no_unsafe_fallback(self):
        def old_rmtree(path, ignore_errors=False, onerror=None):
            raise AssertionError("Unsafe fallback must never be called")
        old_rmtree.avoids_symlink_attacks = True
        plan = self.plan(method="delete")
        with mock.patch.object(helper.shutil, "rmtree", old_rmtree):
            with self.assertRaisesRegex(helper.SafetyError, "Python 3.11"):
                self.apply(plan, execute=True, confirm=plan["digest"])
        self.assertTrue(self.target.exists())
        self.assertFalse(self.journals.exists())

    def test_atomic_trash_move_never_overwrites_destination(self):
        source = self.base / "source"
        destination = self.base / "destination"
        source.mkdir()
        destination.mkdir()
        (destination / "keep").write_text("keep")
        fd = helper._open_dir(self.base)
        try:
            with self.assertRaises(OSError):
                helper._rename_noreplace(fd, "source", fd, "destination")
        finally:
            os.close(fd)
        self.assertTrue(source.exists())
        self.assertEqual((destination / "keep").read_text(), "keep")

    def test_cross_filesystem_trash_is_refused_before_journal(self):
        plan = self.plan()
        real_stat = helper._secure_stat
        def different_device(path):
            metadata = real_stat(path)
            values = list(metadata)
            values[2] = metadata.st_dev + 1
            return os.stat_result(values)
        # Initial candidate validation needs only directory/owner fields;
        # fingerprint does its independent fd metadata checks.
        with mock.patch.object(helper, "_secure_stat", different_device):
            with self.assertRaisesRegex(helper.SafetyError, "cross filesystems"):
                self.apply(plan, execute=True, confirm=plan["digest"])
        self.assertTrue(self.target.exists())
        self.assertFalse(self.journals.exists())

    def test_scan_excludes_symlink_roots_and_agent_caches(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.target.parent / "symlink-cache").symlink_to(outside, target_is_directory=True)
        agent = self.target.parent / "Codex"
        agent.mkdir()
        with mock.patch.object(helper, "_measurement", return_value={"status": "measured", "allocated_bytes": 4096}) as measurement:
            inventory = helper.scan(self.ctx)
        candidate_paths = [item["path"] for item in inventory["candidates"]]
        measured_paths = [str(call.args[0]) for call in measurement.call_args_list]
        self.assertNotIn(str(self.target.parent / "symlink-cache"), candidate_paths)
        self.assertNotIn(str(self.target.parent / "symlink-cache"), measured_paths)
        self.assertNotIn(str(agent), candidate_paths)
        self.assertIn(str(agent), [item["path"] for item in inventory["review_only"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
