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

## P2 修复交付（2026-10-24）

本轮在当前 P1 修复实现上完成 P2-01、P2-02、P2-03、P2-04；未处理 P3 版本显示问题。继续使用 Windows PowerShell 5.1、WinForms、原有 M1–M7 模块与普通 GUI / 管理员执行器分离方式。没有增加生产模块或第三方依赖，没有删除项目文件。

### 修改文件和修复方式

| 文件 | 本轮修改 |
|---|---|
| Collector.ps1 | 在原模块内添加计数器解析辅助函数；先检查空值、整数格式、负值和溢出，再转换字节数。CIM 来源独立失败，保留可验证字段并返回 Partial / Failed，缺失字段始终为 null；Available RAM 使用验证过的 OS 回退值。 |
| Analyzer.ps1 | 使用递增采样序号拒绝迟到消息，结合 UTC / 单调时间发现回拨；清空进程和池趋势，生成新连续段并重新积累窗口。恢复时保留旧记录追加顺序，新记录用单调时间处理跨午夜回拨，仅使用最后连续段，正常重启沿用该段。 |
| Worker.ps1 | 诊断前添加本次采样的单调时间，原顺序采样与有界邮箱不变。 |
| Persistence.ps1 | schema=1 的 system / process JSONL 增加可选 ContinuityId、TimeDiscontinuity、MonotonicSeconds 字段；CaptureEndUtc 仍为 UTC，现有字段和归档格式不变。 |
| ProcessActions.ps1 | 原模块内加入单个后台预验证 / 执行任务。CIM 单次超时 5 秒、身份检查总预算 15 秒，GUI 在 20 秒后显示超时且保留任务互斥。后台执行仍获取原 P1 目标锁并重新核验身份、路径、所有者、会话和服务宿主，发送前再次验证原 Process 对象。观察对象与文件锁在后台完成后交接给 GUI。 |
| MemoryInspector.ps1 | GUI 主线程不再调用同步进程动作；预验证完成且精确匹配 PID / 启动时间 / 名称后才启用按钮，确认期间身份改变则拒绝。操作结果使用独立状态并保留，普通采样继续刷新监控栏。Partial 中缺失计数器显示“不可用”，图表留空，提交变化不再对 null 做减法。审计对话框提供完整的进程和管理员审计两个页签。 |
| GuiV4.ps1 | 沿用现有 WinForms 控件，增加后台检查状态、独立操作结果行和完整审计入口；服务操作反馈也接入独立结果区域。回拨标记清理显示趋势缓存。 |
| SmokeTest.ps1 | 新增 P2-01：空值、空记录、非法字符串、负数、NaN、无穷、浮点、布尔、溢出、真实零提交、零上限、RAM 回退和读取失败。 |
| AnalyzerTest.ps1 | 新增 P2-02：两小时回拨后的完整 30 分钟合成增长窗口、迟到序号、UTC 仍递增时的校时、历史断点、跨午夜恢复、正常重启连续段兼容。 |
| ProcessActionsTest.ps1 | 新增 P2-03：原身份检查函数配合假进程 / 假 CIM，慢查询不阻塞调用者和 WinForms 消息泵、任务有界、超时后不接受晚到结果、执行前 PID 复用、服务宿主 / 读取失败拒绝、锁交接与观察结束释放。所有关闭请求仅调用测试对象。 |
| GuiV4Test.ps1 | 新增 P2-01 / P2-03 / P2-04：真实 GUI 控制函数的空值 KPI / 图表断点、实例匹配与过期按钮门控、连续邮箱刷新保留成功 / 失败 / 超时 / 未知结果、未退出状态，以及超过 100 条的完整进程 / 管理员审计对话框。 |
| PersistenceTest.ps1 | 新增 P2-02：可选连续段元数据和 UTC 的双记录落盘回归，保留原 P1 故障 / 恢复 / 归档 / 锁测试。 |
| docs/M8-ACCEPTANCE.md | 本节交付、执行结果与验收边界。 |

### 实际执行结果

运行环境：Windows 11（NT 10.0.22631），Windows PowerShell Desktop 5.1.22621.6133；测试使用 powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File <测试脚本>。

| 脚本 | 最终退出码 / 结果 |
|---|---|
| SmokeTest.ps1 | 0 / PASS，真实只读采样与 P2 计数器故障回归。 |
| AnalyzerTest.ps1 | 0 / PASS，原动态周期 / 历史 / 诊断测试及 P2 回拨、完整新窗口、跨午夜 / 重启。 |
| ProcessActionsTest.ps1 | 0 / PASS，原 P1 安全锁测试及 P2 后台身份核验 / WinForms 消息泵 / 超时 / 锁交接。 |
| GuiV4Test.ps1 | 0 / PASS，原 GUI / Worker 测试及 P2 空值图表 / 按钮门控 / 采样结果保留 / 完整审计。 |
| PersistenceTest.ps1 | 0 / PASS，原 P1 全部持久化故障注入与 P2 元数据。 |
| PrivilegeSecurityTest.ps1 | 0 / PASS；因本机为非管理员，真实管理员 ACL fixture 明确 SKIP。 |
| ServiceManagementTest.ps1 | 0 / PASS，原服务状态与多进程互斥 / 并发更新回归。 |
| Milestone8Test.ps1 | 0 / PASS，25 个根脚本的 PS5.1 解析及默认拒绝 / 安装分离 / 损坏配置回归。 |

AcceptanceSoak.ps1 -DurationMinutes 1 -IntervalSeconds 5：62.1 秒、12 次真实只读采样、0 数据源失败、0 长缺口；采集 P95 6174.1 ms（包括冷启动），CLI 平均 CPU 0.645%，峰值 Working Set 95.26 MiB。该数据不代表 GUI、管理员操作或 24 小时性能验收。

用原主控制器和 GuiV4 初始化代码建立真实 WinForms 控件，在隐藏窗口中渲染 1300×850 和 1020×690 两种尺寸。独立结果标签高度 49 像素、操作按钮高度 31 像素；人工查看图片确认监控栏、操作结果和审计入口可见。渲染夹具禁用真实采样、真实操作及 UAC，只替换启动/模态等待以生成图片。该检查不代替完整交互和 DPI 验收。

界面技能的 audit_project.py --mode strict 退出码 0；该工具没有 PowerShell / WinForms 源码规则，因此不将其空发现当作原生 GUI 正确性证据。原生 GUI 的证据来自项目回归与实际控件渲染。git diff --check 无错误。

证据保留在项目 .p2-validation：
- regression-core.json、regression-safety.json 和各测试脚本的 .log。
- m8-collector-*.json：真实只读采样遥测。
- gui-1300x850.png、gui-1020x690.png、layout.json：WinForms 渲染与控件边界。
- GuiRender.fixture.ps1：仅用于本次渲染的测试夹具，不属于生产模块。
- premium-audit.json：附属静态审计结果。
故障测试数据继续保留在 test-artifacts / _test-artifacts；无文件清理或删除。

### 兼容性与安全评估

用户配置未修改；已有采样间隔、阈值、日志目录与服务策略格式继续有效。历史仍为 schema=1 / UTC / 原 JSONL 和 ZIP 格式，新连续性字段可缺省，旧历史按追加顺序和 UTC 保守检测断点，新历史额外使用单调时间纠正跨日顺序。单调时间仅用于连续性，不替代 UTC 时间戳。

GUI 普通权限与管理员执行器边界不变。没有自动关闭、自动重试、自动服务恢复、级联或 Startup Type 变更；没有放宽 P1 锁、受保护目标、所有者或审计要求。预检查结果不能当作正式执行权限；后台正式执行仍完整复核。未知状态、查询失败 / 超时与目标变化继续默认拒绝。非管理员进程日志仍是当前用户可修改的操作记录，不能宣称为防篡改安全审计。

本轮自动化和模拟 / 文件级并发回归未发现新增的权限边界退化。已测试的操作均为模拟对象，未向真实进程发送关闭 / Kill，也未操作真实 Windows 服务。

### 未执行及剩余实机验收

- PrivilegeInstallTest.ps1 只允许 fresh disposable Windows runner，脚本明确禁止在用户电脑执行，因此本轮未运行安装 / 卸载 / 真实管理员 ACL 验收。
- PrivilegeSecurityTest.ps1 的管理员 ACL 分支本机 SKIP，不能计为已通过实际 ACL 验证。
- 仍需在隔离环境用专用普通 GUI 测试应用验收慢 / 失败 CIM、选择切换、确认期间 PID 复用、正常关闭 / 强制结束和观察结果；不得使用核心进程。
- 仍需在隔离 Windows VM 验收真实回拨 / 校时 / 休眠和 GUI 可见恢复。本轮 30 分钟恢复窗口由合成 UTC 和单调时间验证，未修改主机时间。
- 仍需专用隔离服务的真实停止 / 恢复、管理员双执行器并发、UAC 取消与保护安装升级。
- Windows 10 / Windows 11 的 24 小时 GUI、托盘退出、DPI / 高缩放、资源和交互矩阵仍未完成；AcceptanceGuiMonitor.ps1 未执行。


## P3 版本与遗留文案统一（2026-10-24）

本轮在 P1 / P2 当前实现上完成 P3-01，VERSION 仍为 0.0.8。未新增生产模块、依赖或配置项，未修改用户配置、历史数据及危险操作流程。

修改文件：
- GuiV4.ps1：在现有模块中新增 Get-MiVersionPresentation，只读解析 VERSION，一次生成窗口标题、托盘文本、服务页和设置页安装提示。缺失、不可读或格式损坏会明确报错，不回退到旧的硬编码版本。
- MemoryInspector.ps1：创建动作状态与窗口前读取版本信息，窗口标题使用统一结果；移除旧的显示版本及“服务仍只读 / 不操作服务”等与当前 M7 架构矛盾的遗留文案。
- ServiceBridge.ps1：移除“先安装 0.0.7”的旧错误提示，改为安装 VERSION 所指的当前发行版。
- Installer.ps1：安装成功提示与 manifest.Version 使用读取且经过原有发行版白名单验证的 sourceVersion。当前仅允许安装 0.0.8，保留 0.0.7 → 0.0.8 升级兼容；没有把显示版本动态化变成任意版本自动受信任。
- GuiV4Test.ps1：新增 VERSION=0.0.8 / 1.2.3 的真实控件赋值绑定回归，验证不修改项目 VERSION 即能驱动各显示位置；覆盖空值、非法值、多行、缺失和不可读文件、托盘长度、安装清单与显示一致性、发行版白名单未放宽及旧 GUI 文案不存在。
- docs/M8-ACCEPTANCE.md：本节记录。

Windows PowerShell Desktop 5.1 下运行 SmokeTest.ps1、AnalyzerTest.ps1、ProcessActionsTest.ps1、GuiV4Test.ps1、PersistenceTest.ps1、PrivilegeSecurityTest.ps1、ServiceManagementTest.ps1、Milestone8Test.ps1：8 个常规回归脚本均退出码 0。最后调整旧说明文案后再次运行 GuiV4Test.ps1 与 Milestone8Test.ps1，均通过。现有 P1 / P2 回归保留并通过。

真实 WinForms 控件初始化及隐藏窗口渲染验证：窗口、托盘、服务页、设置页均为 0.0.8，服务和设置说明可见。截图只验证显示，不代表已执行实际安装或升级。受保护安装 / 卸载测试仍限 fresh disposable Windows runner，本用户电脑未执行；非管理员 ACL 分支仍为 SKIP，不能计为管理员部署验收通过。

证据保留于 .p3-validation：regression-core.json、regression-safety.json、各测试 .log、version-render.json、gui-tab-0.png / gui-tab-2.png / gui-tab-4.png，以及渲染测试夹具。既有 .p2-validation 和故障测试资料均保留。

安全与兼容性：未改动管理员执行器、权限分离、ACL / 哈希 / 版本信任白名单、跨进程锁或确认机制。代码中的明确安全版本列表和历史升级文档继续保留旧版本号，它们不是当前 GUI 显示来源。VERSION 读取只提供显示信息，不提供操作权限。未安装或更新系统中的受保护副本；若需要实际部署，应在隔离验收通过后使用 Installer.ps1 更新。
