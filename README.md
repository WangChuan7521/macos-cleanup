# macos-cleanup

面向 Codex 与 DeepSeek Harness 的 macOS 缓存清理技能。先扫描磁盘占用并解释建议，生成具体计划；用户确认后才执行，最后复核结果。使用本地 Python 标准库，不需要 API 密钥、第三方 Python 包或后台服务。

**扫描 → 计划 → 用户确认 → 执行 → 复核。** 首次请求“帮我清理”不视为对尚未展示清单的授权。

## 安装

将仓库内容放入下列技能目录，确保 `SKILL.md` 直接位于 `macos-cleanup/` 下，并保留 `scripts/`、`references/`、`agents/` 的相对结构。已有同名目录时先核对版本与本地修改。

| 客户端 | 默认安装目录 | 环境覆盖 |
| --- | --- | --- |
| Codex | `~/.codex/skills/macos-cleanup/` | 设置 `CODEX_HOME` 时使用 `$CODEX_HOME/skills/macos-cleanup/` |
| DeepSeek Harness | `~/.dsh/skills/macos-cleanup/` | 设置 `DSH_HOME` 时使用 `$DSH_HOME/skills/macos-cleanup/` |

DeepSeek Harness 也支持共享的 `~/.agents/skills/`；其根目录可由 `DSH_AGENTS_HOME` 或客户端配置覆盖。以实际运行环境的技能根目录为准。安装后在新对话中调用；必要时刷新技能列表或重启客户端。

例如，未设置自定义根目录且目标目录不存在时，使用 Git 安装到 Codex：

```sh
git clone https://github.com/WangChuan7521/macos-cleanup.git ~/.codex/skills/macos-cleanup
```

DeepSeek Harness 可将目标换为 `~/.dsh/skills/macos-cleanup`。不要覆盖已有的本地修改。

```text
使用 macos-cleanup 扫描我的 Mac，给出清理建议和具体计划，等我确认后再执行。
```

支持显式技能调用的客户端可使用 `$macos-cleanup`。流程指令见 [SKILL.md](SKILL.md)，候选判断见 [清理决策规则](references/cleanup-policy.md)。

## 运行要求

- macOS，普通用户权限；不使用 `sudo`，不更改系统权限或完整磁盘访问设置。
- 扫描、规划及移入废纸篓：Python **3.9+**。
- 永久删除及其预演：Python **3.11+**，并支持文件描述符形式的安全 `shutil.rmtree(dir_fd=...)`；能力不足时拒绝操作，不使用不安全回退。

使用现有的合适解释器，并在同一轮扫描、规划、执行中保持一致；技能不会自动安装依赖。

## 手动 CLI

以下命令从仓库根目录运行。为每次扫描选择新的报告目录，放在所有缓存目标之外；脚本将新目录设为私有，已有输出目录必须属于当前用户且权限为 `700`。

```sh
cleanup_python=python3
cleanup_report="$PWD/work/mac-cleanup-run"

"$cleanup_python" scripts/macos_cleanup.py --help
"$cleanup_python" scripts/macos_cleanup.py scan --out-dir "$cleanup_report"
```

阅读生成的 `scan.md` 和 `scan.json`，判断各项用途、重建代价与运行状态。仅选择本次确定要处理的候选 ID：

```sh
"$cleanup_python" scripts/macos_cleanup.py plan \
  --scan "$cleanup_report/scan.json" \
  --ids "<候选ID1,候选ID2>" \
  --method trash \
  --out "$cleanup_report/plan.json"

"$cleanup_python" scripts/macos_cleanup.py apply \
  --plan "$cleanup_report/plan.json"
```

`scan`、`plan` 和默认 `apply` 均不修改清理目标。`plan` 只接受本助手生成且未修改的 `scan.json`，不能替换为其他盘点报告或手工编造候选 ID。默认 `apply` 是预演，**没有 `--dry-run` 参数**。

阅读计划中的精确路径、处理方式、代价及预演结果，关闭使用对应缓存的应用、构建和包管理任务。只有用户明确同意该清单与方式后，才运行：

```sh
"$cleanup_python" scripts/macos_cleanup.py apply \
  --plan "$cleanup_report/plan.json" \
  --journal-dir "$cleanup_report/journals" \
  --execute \
  --confirm "<计划中的完整digest>"
```

**摘要用于检测计划变化，不是用户授权。** 代理必须另行取得明确确认并记录授权范围。永久删除需要以 `--method delete` 生成另一份计划，先预演、说明无法由本工具恢复，再取得对应确认；不能沿用废纸篓计划的批准。

扫描与计划最长有效 24 小时，并绑定当前用户、机器及可用的启动会话。目标变化、过期或环境变化导致检查失败时，应重新扫描与规划。执行失败就停止，依据日志报告已完成与未完成项目。

## 边界与结果解释

- 缓存候选仍需逐项判断；白名单不代表其中所有数据都适合删除。清理可能导致重新下载、重新构建和离线功能受影响。正在使用的目录应延后，指纹检查不能消除并发写入风险。
- 默认移入废纸篓，通常不会立即释放空间，也不自动清空废纸篓。日志提供原路径与新路径，恢复需手动移回并解决冲突，不保证 Finder 的“放回”功能。永久删除无法由本工具撤销。
- 不清理系统文件、快照、应用本体、用户文档、账户数据、配置与密钥、工程源文件、虚拟环境、模型、运行时、容器数据或模拟器。当前代理的缓存、运行环境与会话数据保留。
- 不整目录清空 `~/Library/Caches` 或 `.cache`，不扫荡临时目录，不强退应用、不停止服务。权限不足、超时和扫描截断必须如实报告，不将未知大小视为零。
- 扫描仅查看元数据，有时间与条目上限，不是全盘审计。占用是分配块估算；APFS 共享块、硬链接、压缩、快照及同期写入会影响回收量，执行后以日志和可用空间变化复核。

## 测试与隐私

在可写工作目录使用 Python 3.11+ 运行：

```sh
python3 scripts/test_macos_cleanup.py
```

测试在当前目录的 `work/macos-cleanup-tests/` 下建立临时模拟 home，测试后清除模拟数据，不扫描或清理真实用户缓存。覆盖默认预演、确认参数、摘要篡改、过期与目标变化、符号链接、路径与权限边界等情形；Python 3.9 会跳过永久删除成功用例。

扫描报告、计划和执行日志包含本机路径与元数据，应仅保存在本地私有目录。**公开仓库只提交技能源码、说明与模拟测试；不提交真实机器报告、计划、执行日志或安装清单。**

## 许可证

[MIT](LICENSE)。
