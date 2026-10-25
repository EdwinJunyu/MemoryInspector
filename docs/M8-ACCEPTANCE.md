# MemoryInspector 0.0.9 — Milestone 8 acceptance checklist

**Status: 旧版本 / legacy snapshot; acceptance incomplete.** Automated CI cannot substitute for Windows 10 and 11 desktop validation or a 24-hour GUI run.

## 0.0.9 旧版本备注与后续待办（2026-10-24）

按用户要求，将至今的修复保存为 0.0.9 旧版本快照并提交到远程 main；这不是稳定版或 P1–P3 全部验收通过的声明。下方旧章节保留各轮当时的版本、结果和提交状态，属于历史记录。原始机器进程列表、截图、日志、测试夹具和源码备份仅保留本地，不随源码发布；本节给出公开结果摘要和未完成范围。

| 状态 / 优先级 | 项目与备注 | 后续工作 |
|---|---|---|
| 已测试未通过 / P1-01 | 最终 30 分钟窗口原始 360 点归入 343/361 槽（95%）；六段 50/60、52/60、60/60、60/60、60/60、61/61，首段低于原 85%。存在 17 次归槽碰撞，累计完成相位漂移约 2.558 秒。修改前后分析器的 24967 点哈希及完整报告相同。 | 修复调度/抖动归槽问题，增加回归并重新完成实机窗口；不降低阈值、不填补缺样。 |
| 已测试未通过 / P2 | GUI 35 分钟平均 CPU 0.0914%，Working Set 均值 194.42 MiB、采样峰值 210.08 MiB；观察后读取的 OS 存活期峰值 234.94 MiB。未重现此前数百 MiB 增长，但严格 200 MiB 峰值目标仍未达到。 | 继续优化瞬时分配/恢复峰值，验证长期资源；不能宣称无泄漏。 |
| 未完成 / P2–P3，按实际影响分级 | 真实系统 DPI 切换、多屏、端到端输入延迟、最终版五页人工确认和完整托盘/快捷键/滚动组合。普通两尺寸表头和图例已通过控件回归及此前用户截图；125%/150% 模拟图有整页超界，不能记为真实 DPI 通过。 | 在真实显示设置下验收；纯显示问题通常 P3，操作不可用为 P2，安全提示/目标受影响需重新评估。 |
| 未测试 / 通常 P2，严重后果另评 | Windows 10；Windows 10/11 各自 24 小时 GUI/托盘长稳。当前本机实测仅为 Windows 11 的有限时长。 | 完成对应系统和 24 小时矩阵；未测系统不宣称已验证兼容。 |
| 未测试 / P1–P2，按后果分级 | 真实磁盘满、存储失败/恢复、时钟回拨/校时、休眠/唤醒、真实 PID 复用。合成/文件级回归不等于实机通过。 | 在隔离 Windows 环境注入故障，检查历史、身份连续性和默认拒绝。 |
| 未测试 / 安全路径 P1 | 受保护安装/升级/卸载及跨路径 ACL/清单、真实 UAC 取消、管理员执行器并发和部署后的重放/篡改；普通测试 GUI 的关闭/强制结束；专用允许名单服务的停止/恢复/依赖/自恢复/超时。 | 仅使用一次性 Windows VM 和专用测试目标。此前临时目录管理员 ACL 和普通用户写入拒绝已验证，但不能代替完整部署。未验收前不宣称危险操作可用于生产。 |

以上未通过/未测试项目由本版本明确留待后续处理，既有安全检查继续保留。0.0.9 只精确更新本发行版安装/执行版本门控；升级来源仅显式允许已知 0.0.7/0.0.8/0.0.9，当前执行器默认只信任 0.0.9，M7 必需组件、Recovery Ledger、ACL、哈希、UAC、重放和审计要求不减。常规回归覆盖不冒充真实管理员部署。

本节实机指标来自版本递增前的 0.0.8 修复版。0.0.9 版本对齐后，以 Windows PowerShell 5.1 / RemoteSigned 重新执行 SmokeTest、PersistenceTest、AnalyzerTest、GuiV4Test、ProcessActionsTest、PrivilegeSecurityTest、ServiceManagementTest、Milestone8Test，8 个常规脚本均退出码 0。新增信任回归执行真实验证函数，覆盖 0.0.9 默认接受、旧版默认拒绝但显式升级允许、未知版本拒绝、M7 必需组件及账本缺失拒绝；ACL 仅在独立测试目录中模拟，普通权限的真实管理员 ACL 分支仍 SKIP。独立代码审阅未发现新引入的提交阻塞项。版本递增本身没有重跑新的 35 分钟或 24 小时验收。

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
- [ ] Upgrade from protected 0.0.7/0.0.8 to 0.0.9 preserves allowlist/audit and enforces manifest.
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

## 2026-10-24 正式启动、采样和资源观察修复

本轮继续保持原有模块、Windows PowerShell 5.1、普通 GUI / 保护执行器分离、85% 覆盖率和默认拒绝检查。没有新增生产模块，没有提交或推送。

- 正式入口仍为 RemoteSigned。已将启动失败说明和验证下载来源的步骤写入原启动器及 README；启动器不会改策略或自动解除标记。本机 PrivilegeSecurity.ps1 / PrivilegeBridge.ps1 与当前提交及 GitHub 上游 blob 一致，保存来源流证据并经用户明确批准后，仅解除这两个文件的 ZoneId=3 标记。它们的源码字节未变。这是一次性本机信任处理，不是自动信任后续下载。
- 实测约 470 个进程的枚举约 46 ms、内存字段约 3 ms，旧 Process.StartTime 路径约 3.54 秒。在原 Collector.ps1 内改用 Windows GetProcessTimes + PROCESS_QUERY_LIMITED_INFORMATION（0x1000）的只读句柄，仍每轮读取真实创建时间，不缓存 PID 身份、不申请终止/写内存/调试权限；SafeProcessHandle 每次释放。失败保留 null / Partial，进程动作原有身份、所有者、会话、服务宿主及执行前检查不变。参考 [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)。
- 首次完整 GUI 初始化遗漏 ProcessTrend，导致首条邮箱样本在 KPI / 表格刷新前抛出 null 异常；原 GuiV4.ps1 初始化中补齐空缓存。新回归创建完整真实控件再执行首条邮箱，而非由测试预先填好缓存或替换 Grid 刷新。
- 上轮失败的多 Worker 观察器属于临时夹具，原始失败证据继续保留。本轮统一使用已有 AcceptanceGuiMonitor.ps1；新增 -JobsPath 支持多目标，并修复 PS5.1 JSON 数组嵌套、校验精确 PID/创建时间、CPU 差分、首样本 CPU 未知、区域格式 CSV 及零观测失败摘要。GUI 与 BackendJobs 的 SourceKind 和各目标结果分开保存。运行中的 CSV 用 FileShare.ReadWrite 读取，不能仅根据目录枚举暂时报出的 0 字节判定没有观测数据。
- SmokeTest 新增真实创建时间一致性、无效 PID、句柄释放和慢旧 getter 未调用回归；Milestone8Test 新增 RemoteSigned 的真实下载标记拒绝/显式信任夹具，以及观察器的多目标、损坏/重复身份、PID 复用、CPU、区域格式和空结果回归。管理员 ACL 夹具改为保留在项目 test-artifacts，不删除资料。

8 个常规回归在 RemoteSigned 下全部通过；另已通过用户确认的 UAC 执行原 PrivilegeSecurityTest 的真实管理员 ACL 分支，独立夹具被设置为 SYSTEM / Administrators 可写、Users 只读。普通用户取得测试文件写句柄被 UnauthorizedAccessException 拒绝，文件哈希未变。该临时目录测试不代替 Program Files / ProgramData 的完整保护安装和跨路径信任验收。用户本轮选择先完成本机 GUI 与临时目录 ACL；PrivilegeInstallTest、安装/卸载和真实服务操作继续留待隔离 Windows 环境。

最终长时数据、实际资源、已完成及未完成清单以项目 `.repair-acceptance-20261024-185941/REPORT.md` 为准。原 `.live-acceptance-20261024-175103` 失败证据保留，不改写为通过。

本轮最终结果：正式普通权限 GUI 的 395 对真实落盘记录首尾跨度 1972.622 秒；5 秒最终窗口 358/361 个有效槽（99.2%），六段均满足原 85% 要求。Collector 平均 1271.60 ms、P95 1636 ms、最大 3208 ms。受控增长与稳定进程各自然运行 32 分钟；原分析器的真实数据回放与用户实时 GUI 截图分别显示疑似持续增长、暂无明显增长。资源观察器完整运行 1920 秒、192 条，GUI 平均归一化 CPU 0.1503%、峰值 1.55%，Working Set 峰值 895.74 MiB，**内存未通过 <200 MiB 目标**；截图中的表头/图例裁切和完整 DPI/交互仍未通过。受保护安装、真实服务/进程动作、真实故障/回拨/休眠、Windows 10 与 Win10/11 各 24 小时验收继续未测，不能声明 P1–P3 全部通过。

## 2026-10-24 GUI 内存、表头和图例修复

总览缓存原先保留每轮完整进程快照，现只复制系统图表需要的标量；当前完整快照继续用于界面和身份核验。原 GuiV4 / Analyzer 模块内改用紧凑值类型保留全部 30 分钟样本，历史恢复按行投影释放 JSON 属性图，raw/ZIP 与原 schema=1 兼容。有效身份的 null/负计数器仍保留连续段断点，之后由原规则拒绝其数值，不能拼接断点两侧的证据。5 秒周期、85% 总体及分段覆盖要求、Int64/null 语义和所有危险操作检查未放宽。

修正现有 Top/Fill 控件 Dock 顺序，标题不再覆盖表头、图例、顶端刻度或详情首行。表头自动换行/增高，窄表格保留最小列宽并使用内部水平滚动。表格改为复用行、仅更新变化单元格，Tag 每轮替换为最新对象；选择和操作门控仍按精确 PID/创建时间核验，PID 复用或过滤不能继承旧目标。

同输入的独立缓存实验（361 轮×500 进程）：总览保留托管内存增量 291.354→1.799 MiB，进程图表 21.362→2.584 MiB，分析器 69.286→3.931 MiB。真实历史恢复的 326 条记录/365 实例/22257 点逐点 SHA-256 相同，独立恢复峰值 320.86→221.82 MiB；恢复约 30 秒，不能称为快速启动通过。可见表格控件刷新均值约 749.74→119.63 ms，此为刷新计时，不是端到端输入延迟。

8 个常规 PS5.1 回归在 RemoteSigned 下全部通过，保留原安全测试，并新增缓存隔离、完整窗口、精确计数、null 连续段屏障、复用行身份/选择/过滤、真实完整控件首条刷新及 UTF-8 BOM 检查。布局夹具生成 30 张图；100% 的实际 1300×850 / 1020×690 五页检查中表头、图例及顶端刻度可见。125%/150% 自有控件缩放的 20 张图虽无标题/内容重叠，但人工复核发现整页右侧超界，保留为待复核模拟实验，不能记为布局或 DPI 全部通过。自有控件 Form.Scale 不代替真实系统 DPI 切换和多屏实测。

当前任务完整证据及最终实机结论见 `.gui-memory-layout-20261024-200746/REPORT.md`。初轮不足时长、资源超标、编码错误的夹具及弃用性能实验均保留，不能改记为通过。最终正式 GUI 观察独立记录于 `verified-gui-observer`，不得用合成缓存或隐藏控件结果替代。继续保持 CPU <1%、Working Set <200 MiB 和正常响应 <1 秒目标；未完成 Windows 10、真实 DPI/故障/服务/受保护部署及 Win10/11 各 24 小时验收，不能宣称 P1–P3 全部通过。未提交或推送。

最终正式观察为 35 分钟/210 条：平均归一化 CPU 0.0914%，Working Set 均值 194.42 MiB、采样峰值 210.08 MiB，之后读取的 OS 存活期峰值 234.94 MiB。第 5–10 与 30–35 分钟均值分别为 194.103 和 195.025 MiB，没有重现原先数百 MiB 增长，但严格内存峰值目标仍未通过。

真实落盘 412 对、跨度 2057.558 秒，0 解析/重复/配对/序号/时钟异常；Collector 均值 1474.13 ms、P95 1830 ms。最终回放 343/361 槽（95%），六段 50/60、52/60、60/60、60/60、60/60、61/61，首段低于原 85%，所以诊断仍为证据不足，不能算采样充分性通过。修改前后分析器在同一窗口的 24967 个点哈希和完整报告相同，排除本轮存储优化造成该差异；360 个原始点有 17 次归槽碰撞，累计完成相位漂移约 2.558 秒，仍需后续修复/实测，不能放宽检查。
