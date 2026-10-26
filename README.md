# MemoryInspector

**Version 0.0.9 — 旧版本（Legacy snapshot / acceptance incomplete）**

这是保留至今修复的旧版本快照，未完成全部实机验收，不标记为稳定版。已知未通过：5 秒采样最终窗口首段仅 50/60 个有效槽（低于原 85% 要求），GUI Working Set 采样峰值 210.08 MiB（目标 <200 MiB）。两项均保留检查，待后续修复。

未完成的真实 DPI/多屏、Win10、Win10/11 各 24 小时、真实存储/时钟/休眠故障、受保护部署/UAC 及专用进程/服务动作验收，详见 [验收备注和待办](docs/M8-ACCEPTANCE.md)。此前 35 分钟实测基于修复中的 0.0.8；0.0.9 版本对齐后的常规回归另行记录，不冒充重跑全部实机项目。原始进程记录、截图、临时日志和备份保留本地，不随源码提交。

MemoryInspector is a local Windows PowerShell 5.1 application for memory monitoring, anomaly analysis and manually confirmed management operations. It is NOT a one-click cleaner. High Private Bytes or growing memory does not prove a leak or safe release.

## V3-M1 — System Memory Attribution（开发阶段）

本轮在原有模块内实现只读归因，需求来源为 [v3 冻结规格](https://docs.google.com/document/d/1GVln-oZKuIPkIR1C-Bh3JouyMhEO0z6X-dAscPpTHr4/edit) 第 4 节与 V3-M1。VERSION 保持现有版本；此里程碑不是 Stable v3 发布，也没有改变受保护安装的版本信任规则。

- 打开 **Attribution · 归因**：查看系统 Commit、Commit Limit/Headroom、两类 Pool、可读进程 Private Bytes 汇总及未解释差额。RAM 的总量、可用量、Cache/Standby 单独展示；压缩量没有可靠来源时显示不可用。
- 切换进程实例、可执行路径、当前父子关系视角；实例视角用 Ctrl/Shift 多选形成临时逻辑组。组只用于本次快照的诊断，无任何批量操作能力。路径不是签名/文件哈希身份，不同路径即使同名也不会合并；缺少路径时保留单实例，无法核验的父 PID 不建立关系。
- 选择结果可查看实际 UTC 时间、目标周期、有效/预期样本数、缺口、来源、可信度和局限。保留 5–60 秒可配置周期及原默认值；新系统归因窗口从本次后台启动开始积累，旧历史不伪装为新归因证据。原有进程历史恢复继续使用。
- Finding 的 `ObservedBytes` 为当前观测值；`GrowthBytes` 为窗口内实际首末证据差，不是预测，也不同于旧诊断的分段中位数增长。Pool 持续增长需足够跨度、覆盖率、分段覆盖、最大缺口与至少 4/5 个上升分段，并达到 128 MiB；只能提示进一步调查，不能定位驱动或证明泄漏。
- 全进程采集不完整时，汇总标记 Partial，只显示可读部分；不据此给出完整汇总增长。Commit 减去 Private Bytes 的残差保持 Unresolved，不能把 Pool 或 Working Set 加进去凑成 Commit。Working Set 仍在原进程页逐个查看，不求和当作 RAM 总占用。
- 系统 Finding 与可选 RAM 字段写入现有 system JSONL；路径及父实例元数据写入原 process JSONL，沿用原配额和 schema=1 的兼容读取。旧记录缺少字段时不补零、不删除。归因结果不能作为 ActionGrant 或任何高权限凭证。

尚未开放 WPR、Watchdog、Heap 配置、WPAExporter、ActionGrant；它们属于后续独立阶段。开发验证与已知限制见 [项目验收备注](docs/M8-ACCEPTANCE.md)。

### 归因页界面约定

本次为现有 Windows 桌面界面的局部扩展，复用 `New-MiV4DataGrid`、`New-MiLabel` 和主窗口的配色/中文字体，不创建新的 UI 模块或改变已有操作页。Microsoft YaHei UI、浅色背景 `#F3F6FB`、正文 `#17283E`、分隔线 `#DDE5EE` 仍由 MemoryInspector.ps1 统一拥有。原生 TabControl/ComboBox/DataGridView 负责键盘、焦点和内部滚动；归因页的多选是只读诊断特例。未知值显示“不可用”，失效结果清空，选择仅跟随精确实例；后台采集与趋势分析在 Worker 中执行，界面只排版结果。设置、历史、服务及危险确认流程沿用原行为。

## Requirements and launch

- Windows 10/11 x64, Windows PowerShell 5.1, built-in WinForms / .NET Framework; no Python or third-party runtime.
- Review downloaded scripts. Start the GUI without elevation using Run_MemoryInspector.cmd.
- The launcher retains RemoteSigned. If Windows blocks an unsigned downloaded script, first compare that exact file with the trusted repository/release, then explicitly trust only the verified file. The launcher does not lower execution policy or automatically unblock a directory. Folder write permission alone does not resolve a download-origin block.
- The UI supports processes, system overview, service analysis, history and settings. Minimize to tray to continue monitoring; use explicit Exit to quit.

## Protected service management

For service operations, inspect Installer.ps1 and run it in an explicitly elevated Windows PowerShell 5.1 session. It installs a protected copy in Program Files with ACL-checked policy/audit under ProgramData. Use that installed GUI with explicit UAC confirmation; allowlist entries NEVER override safety checks for critical targets and dependents. Do not start a copied elevated executor from an untrusted folder.

To remove the protected installation, review Uninstaller.ps1 and follow its confirmation prompts from an elevated shell. User history and protected audits are retained by default.

## Developer tests and release status

- Regression: SmokeTest.ps1, PersistenceTest.ps1, AnalyzerTest.ps1, GuiV4Test.ps1, ProcessActionsTest.ps1, PrivilegeSecurityTest.ps1, ServiceManagementTest.ps1.
- New M8 tests: Milestone8Test.ps1 (safe fail-closed and corrupted-settings fixtures), AcceptanceSoak.ps1 (read-only collector soak).
- Protected disposable Windows-runner install test: PrivilegeInstallTest.ps1 (including uninstall and protected audit retention).
- Detailed manual Windows 10/11 and 24-hour GUI acceptance: docs/M8-ACCEPTANCE.md.

**Legacy snapshot, not declared stable.** Windows Server CI, brief collector soak and source validation do not prove Windows 10/11 desktop compatibility or 24-hour GUI performance.

- For 24-hour GUI process resource monitoring on a desktop OS, run AcceptanceGuiMonitor.ps1 against the GUI PowerShell PID; see docs/M8-ACCEPTANCE.md. The external observer is read-only and does not replace interactive GUI checks.
- The same observer accepts `-JobsPath <backend-jobs.json>` for isolated backend tests. Each entry must have a distinct positive `Pid` and exact `StartUtcTicks`; GUI results and backend resources remain separate. A zero-observation run writes a failure summary and exits unsuccessfully.
