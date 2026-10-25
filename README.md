# MemoryInspector

**Version 0.0.9 — 旧版本（Legacy snapshot / acceptance incomplete）**

这是保留至今修复的旧版本快照，未完成全部实机验收，不标记为稳定版。已知未通过：5 秒采样最终窗口首段仅 50/60 个有效槽（低于原 85% 要求），GUI Working Set 采样峰值 210.08 MiB（目标 <200 MiB）。两项均保留检查，待后续修复。

未完成的真实 DPI/多屏、Win10、Win10/11 各 24 小时、真实存储/时钟/休眠故障、受保护部署/UAC 及专用进程/服务动作验收，详见 [验收备注和待办](docs/M8-ACCEPTANCE.md)。此前 35 分钟实测基于修复中的 0.0.8；0.0.9 版本对齐后的常规回归另行记录，不冒充重跑全部实机项目。原始进程记录、截图、临时日志和备份保留本地，不随源码提交。

MemoryInspector is a local Windows PowerShell 5.1 application for memory monitoring, anomaly analysis and manually confirmed management operations. It is NOT a one-click cleaner. High Private Bytes or growing memory does not prove a leak or safe release.

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
