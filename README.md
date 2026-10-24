# MemoryInspector

**Version 0.0.8 — Milestone 8 release-candidate tooling**

MemoryInspector is a local Windows PowerShell 5.1 application for memory monitoring, anomaly analysis and manually confirmed management operations. It is NOT a one-click cleaner. High Private Bytes or growing memory does not prove a leak or safe release.

## Requirements and launch

- Windows 10/11 x64, Windows PowerShell 5.1, built-in WinForms / .NET Framework; no Python or third-party runtime.
- Review downloaded scripts. Start the GUI without elevation using Run_MemoryInspector.cmd.
- The UI supports processes, system overview, service analysis, history and settings. Minimize to tray to continue monitoring; use explicit Exit to quit.

## Protected service management

For service operations, inspect Installer.ps1 and run it in an explicitly elevated Windows PowerShell 5.1 session. It installs a protected copy in Program Files with ACL-checked policy/audit under ProgramData. Use that installed GUI with explicit UAC confirmation; allowlist entries NEVER override safety checks for critical targets and dependents. Do not start a copied elevated executor from an untrusted folder.

To remove the protected installation, review Uninstaller.ps1 and follow its confirmation prompts from an elevated shell. User history and protected audits are retained by default.

## Developer tests and release status

- Regression: SmokeTest.ps1, PersistenceTest.ps1, AnalyzerTest.ps1, GuiV4Test.ps1, ProcessActionsTest.ps1, PrivilegeSecurityTest.ps1, ServiceManagementTest.ps1.
- New M8 tests: Milestone8Test.ps1 (safe fail-closed and corrupted-settings fixtures), AcceptanceSoak.ps1 (read-only collector soak).
- Protected disposable Windows-runner install test: PrivilegeInstallTest.ps1 (including uninstall and protected audit retention).
- Detailed manual Windows 10/11 and 24-hour GUI acceptance: docs/M8-ACCEPTANCE.md.

**Release candidate, not declared stable.** Windows Server CI, brief collector soak and source validation do not prove Windows 10/11 desktop compatibility or 24-hour GUI performance.

- For 24-hour GUI process resource monitoring on a desktop OS, run AcceptanceGuiMonitor.ps1 against the GUI PowerShell PID; see docs/M8-ACCEPTANCE.md. The external observer is read-only and does not replace interactive GUI checks.
