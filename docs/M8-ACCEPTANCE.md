# MemoryInspector 0.0.8 — Milestone 8 acceptance checklist

**Status: release candidate.** Automated CI cannot substitute for Windows 10 and 11 desktop validation or a 24-hour GUI run.

## Automated acceptance (safe)

- Windows PowerShell 5.1 parsing of all project scripts.
- Existing M1–M7 regression tests, with M8 fail-closed invalid-input and damaged-settings tests.
- Short read-only collector telemetry probe on GitHub-hosted Windows Server runner.
- Disposable runner protected installation, replay and hash-tamper rejection, safe uninstall preserving protected audit/policy.
- All required jobs must pass before considering a stable release.

## Manual Windows 10 AND Windows 11 acceptance (VM / non-production PC)

Record commit SHA, OS build, PowerShell version, start/end times, result, and sanitized evidence.

- [ ] Non-admin STA WinForms GUI starts without unexpected UAC.
- [ ] Processes, Overview, Services, History and Settings screens render and remain responsive.
- [ ] Memory counters match the meaning of Task Manager / Performance Monitor, not necessarily the same refresh timestamp.
- [ ] Tray minimization keeps sampling; explicit Quit stops it and no elevated child remains.
- [ ] Inaccessible process metrics show unknown/partial, never fabricated zero.
- [ ] PID reuse, process restarts and sleep/resume do not splice unrelated history.
- [ ] Reopen app: JSONL 7-day raw/90-day aggregate policy, rotation, truncated-tail repair, and disk budget are consistent.
- [ ] Confirmed graceful close affects only the chosen disposable GUI application; cancellation does nothing.
- [ ] Danger mode disabled by default; forced termination tested only with a disposable, unsaved-data-free test app.
- [ ] Unknown/system/critical/service-host processes cannot be forcibly terminated.
- [ ] UAC cancellation, invalid target, replay, policy tamper and missing audit all fail closed.
- [ ] Only an approved, disposable test service can be stopped and manually restarted.
- [ ] Running dependent service, auto-restart and timeout do not cause cascade, retries, host kill or startup type edits.
- [ ] Release report distinguishes target process bytes from system net Commit changes.
- [ ] Upgrade from protected 0.0.7 to 0.0.8 preserves allowlist/audit and enforces manifest.
- [ ] Uninstaller removes only controlled files and retains user data and privileged audit by default.
- [ ] Inject storage errors, truncated JSONL, access-denied CIM, disk full, sleep/resume on isolated test host.
- [ ] Measure idle GUI CPU target <1%, working set target <200 MiB, normal UI response target <1 second.
- [ ] Stress hundreds of processes and ensure sample backpressure does not hang GUI.
- [ ] Real GUI remains open or in tray for >=24 hours with no crash; evaluate trend, leaks, missed samples.

## Read-only collector soak

On each desktop OS, launch from Windows PowerShell 5.1:

    powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\AcceptanceSoak.ps1 -DurationMinutes 1440 -IntervalSeconds 5

This generates a JSON report with sample validity, gaps, P95 collector time and *CLI collector* resource consumption. Run separately from the 24-hour GUI observation. These numbers are not GUI resource metrics.

## Stable release gate

Do not create an official Stable v2 release or tag until automated checks AND desktop Windows 10/11 manual checks pass, especially all safety-critical cases. Keep unverified privileged features disabled. An unrun 24-hour test must remain NOT TESTED, not PASS.

For rollback, preserve audits/policy and user data. A downgrade may require manual verification of protected ACLs and manifest; the installer does not promise automatic downgrade.


## Read-only 24-hour GUI resource observer

While the GUI is already running, identify its own powershell.exe PID (avoid confusing it with the separate elevated executor). From a SECOND Windows PowerShell 5.1 terminal run:

    .\AcceptanceGuiMonitor.ps1 -TargetPid <GUI_PID> -DurationMinutes 1440 -IntervalSeconds 10

This observes the *actual GUI process* and saves per-interval RAM, Private Bytes, normalized CPU and window responsiveness to CSV, plus JSON summary. It never kills or starts the target. PID + creation time are checked on every sample. Use it alongside actual human/automation UI-latency checks; responsiveness based on MainWindowHandle is informative, not definitive. Do not interpret raw observer results as proof of full acceptance.

## P1 修复交付范围（2026-10-23）

本轮只处理 P1-01 至 P1-05，保持 Windows PowerShell 5.1、现有 M1–M7 模块、普通 GUI / 管理员执行器边界和默认拒绝策略。没有新增业务模块、第三方依赖或自动服务控制。

| 问题 | 实现与兼容策略 | 针对性回归 |
|---|---|---|
| P1-01 | 默认 5 秒，保留既有 5–60 秒用户设置；以时间槽、30 分钟跨度、85% 总体及分段覆盖率和增长趋势共同判定。动态缓存保留完整窗口；周期切换重建趋势，暂停/补采不填平时间缺口。Worker 串行采样、有界队列、单调计时、不积累补排任务。 | AnalyzerTest：5/7/10/20/30/60 秒、稳定/增长、抖动、缺样、缺口、补采、周期切换、raw/ZIP 恢复；GuiV4Test：完整图表窗口、设置替换、超时采集单任务及状态恢复。 |
| P1-02 | 原始文件 SHA-256；写入后重开 ZIP，完整读取解压流核对哈希；全部来源条目校验后才移除原始 JSONL。pending/failed 归档有明确名称，错误保留源文件。 | PersistenceTest：正常恢复、同长度不同内容、坏 ZIP、归档故障和原文件保留。 |
| P1-03 | 服务在管理员执行器调用的服务模块内取得目标独占文件锁；Allowlist / Ledger 分别覆盖完整读改写事务。进程按 PID + 启动时间取得跨 GUI 锁，发送后保留状态防止重复。异常退出由 OS 释放句柄，未知结果仍拒绝重发。 | ServiceManagementTest / ProcessActionsTest：真实第二 PowerShell 进程争锁、不同请求及大小写同目标、并发两条策略/恢复记录、崩溃释放、未知状态拒绝。PrivilegeInstallTest 增加真实保护目录锁 ACL 检查。 |
| P1-04 | 临时 / 永久故障分开；30 秒起退避、最长 300 秒一次恢复检查，核对目录、设置、文件尾和独占写锁。损坏数据保留，部分追加失败只回滚本次字节；不重放故障期丢失采样。恢复后 GUI 恢复正常保存状态。 | PersistenceTest：锁住文件后恢复、退避、多进程独占、部分追加回滚、分文件写入中断防重复、损坏设置/文件拒绝并保留。 |
| P1-05 | StopRequested 仅代表请求；StopConfirmed / 旧版明确确认的 Stopped 才可恢复。停止/恢复成功、拒绝、超时、未知均记录状态与审计；超时或未知不会自动重试。恢复前重新核对身份、策略、依赖和当前状态，不修改 Startup Type。 | ServiceManagementTest：SCM 模拟成功、明确拒绝、超时、查询异常、最终身份/状态不明及旧 StopRequested 拒绝；审计状态转换。 |

修改文件：Analyzer.ps1、AnalyzerTest.ps1、Worker.ps1、MemoryInspector.ps1、GuiV4.ps1、GuiV4Test.ps1、Persistence.ps1、PersistenceTest.ps1、ProcessActions.ps1、ProcessActionsTest.ps1、ServiceManagement.ps1、ServiceManagementTest.ps1、PrivilegeInstallTest.ps1、AcceptanceSoak.ps1、.github/workflows/powershell-tests.yml，以及本文档。

数据兼容：JSONL 和保护状态仍为 SchemaVersion=1；IntervalSeconds 是可选字段，旧历史无此字段仍可读取，并按实际时间戳保守审核。用户已有采样周期与其他设置保留。旧 StopRequested 不升级为“成功停止”；超时/未知记录需人工核查。持久化写锁已扩至跨 Windows 会话，升级前应退出所有旧版实例。

安全边界：未弱化进程身份二次验证、服务保护名单、UAC/管理员确认、安装清单、ACL、防重放及审计。进程锁状态位于用户数据目录，是防重复控制，不属于防篡改管理员审计。持久化永久故障、未知服务结果需要人工处理，不能自动删文件或清除记录来恢复。

本机验证结果和未完成项目会在下面记录；不会把 mock 回归或短时采集计作受保护安装、真实服务状态变化、30 分钟 GUI 或 24 小时实机验收。
### 本机最终验证结果

宿主：Windows 11 build 22631，Windows PowerShell Desktop 5.1.22621.6133；在原项目目录执行最终版本。

| 测试脚本 | 最终结果 |
|---|---|
| SmokeTest.ps1 | PASS：真实只读采集，456 个进程记录。 |
| PersistenceTest.ps1 | PASS：归档内容哈希、原文件保留、临时恢复、退避、部分写回滚、多进程及跨线程锁。 |
| AnalyzerTest.ps1 | PASS：5/7/10/20/30/60 秒、动态覆盖和容量、端点抖动/缺口/切换/历史恢复。30 分钟窗口为合成时间戳测试。 |
| GuiV4Test.ps1 | PASS：缓存完整窗口、已有设置替换、采样超时仍单任务、有界队列、保存失败后再次调用和状态发布。未启动真实 WinForms。 |
| ProcessActionsTest.ps1 | PASS：模拟进程动作、真实跨进程锁、重复请求拒绝、追加状态、空文件/半写/非法 UTF-8/JSON 拒绝。 |
| PrivilegeSecurityTest.ps1 | PASS；非管理员环境的实际 ACL fixture 明确 SKIP，不计为真实 ACL 通过。 |
| ServiceManagementTest.ps1 | PASS：模拟 SCM 状态转换、目标锁、真实双子进程 Allowlist/Ledger 更新、崩溃释放。 |
| Milestone8Test.ps1 | PASS：25 个根目录脚本的 PS5.1 解析、请求默认拒绝、损坏配置保留、GUI/执行器分离静态检查。 |

另外运行 AcceptanceSoak.ps1 -DurationMinutes 1 -IntervalSeconds 5：60 秒、12 个采样、0 次数据源失败、0 个长缺口；CLI 采集 P95 为 6050.1 ms（包含冷启动），平均 CPU 0.667%，峰值 Working Set 92.62 MiB。该数据只代表短时只读采集，不代表 GUI 性能。

可复查证据：项目 .p1-validation/final-regression-results.json、.p1-validation/final-regression-output.txt、.p1-validation/m8-collector-*.json；故障测试数据保留在 test-artifacts。初轮发现的测试资料跨 C/D 盘移动失败已修复，最终八脚本全部退出码 0；初轮输出保留供追溯。修改前源码保存在项目 P1-originals-20261023-233832。

未运行 / 仍需实机验收：

- PrivilegeInstallTest.ps1：只允许 fresh disposable Windows runner；本机为用户环境，未执行安装/卸载和实际管理员锁 ACL 验收。
- 专用隔离测试服务的真实停止/恢复、两个真实管理员执行器并发、UAC 取消与受保护安装升级。
- 非管理员 GUI 默认 5 秒运行至少 30 分钟，设置切换、休眠/唤醒、存储失败/恢复的可见反馈及响应时间；该项不能由合成窗口回归代替。
- Windows 10 / Windows 11 各自的 24 小时 GUI、托盘退出、DPI、资源和交互验收；AcceptanceGuiMonitor.ps1 需真实 GUI PID，因此本轮未执行。

安全评估：静态检查和模拟 / 文件级并发回归未发现新的阻塞性安全问题；真实管理员部署路径尚待上述验收。未知进程锁状态、未知服务操作和永久数据损坏继续默认拒绝。锁文件 / 失败归档 / 测试证据为保留资料，不应盲目删除；退出所有旧版实例后再升级，避免旧版 Local 写锁与新版 Global 写锁并存。

本地 Git 历史已基于 GitHub main 的 00a0f1b 恢复；P1 修复仅作本地提交，不推送远程。P2/P3 保留后续处理；只随 P1 连续性处理安全清理了分析窗口回拨边界，并修复了采样设置保存所需的 PS5.1 File.Replace 空引用绑定。