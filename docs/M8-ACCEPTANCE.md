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

## 2026-10-25 V3-M1：System Memory Attribution

需求来源是 v3 冻结规格第 4 节及 V3-M1，起始提交 `3d2ee903e6dafe63c74860f285c3aa811f6036b9`。本轮实现、Review 审阅后仅创建本地提交，不推送远程。VERSION 保持 0.0.9，不把 M1 开发完成冒充 Stable v3 或更新安装版本信任。未新增生产模块，未删除既有文件，未执行安装、服务操作、进程终止、WPR 或系统配置修改。

### 实现与统计口径

- Collector：增加可选 Cache/Standby；压缩量无可靠来源时保持 null。使用只读 limited-query 句柄绑定映像路径与创建时间，Toolhelp 获取父 PID，再核验父子创建时间。路径仅供诊断分组，不是签名或文件身份授权。创建时间晚于枚举前边界，或两次身份查询不同，均清除实例/路径关联并标记 Partial，独立可读数值仍保留。
- Analyzer：版本化 AttributionFinding 分别报告 Commit/Limit/Headroom、Paged/Nonpaged Pool、可读 Private Bytes 汇总与 Unresolved 残差；RAM 独立。分组区分实例、可执行路径、当前可验证父子关系及用户逻辑组，标注统计口径及成员完整性。无可信身份的记录不参与实例分组。
- 质量：30 分钟窗口使用实际 UTC、目标周期、独立时间槽、跨度及最大缺口，不补零、不插值。新 Finding 使用严格观察边界，原诊断保留半周期端点容差；周期切换/时间回拨重建系统归因窗口。Pool 增长不能确定泄漏或指定驱动；Commit 残差可能为负，不能通过加入 Pool/Working Set 凑平。
- 持久化：原 system/process schema=1 新增可选字段，Finding 自带 SchemaVersion；原历史、配额及读取继续工作。新系统归因从本次 Worker 启动积累，不伪造旧数据缺失的身份和质量；原进程历史恢复保留。
- GUI：新增只读 Attribution 页，后台分析，UI 只显示结果。实例视角 Ctrl/Shift 多选形成临时逻辑组，无批量操作能力；PID 复用不继承选择。详情显示来源、实际 UTC、有效/预期样本、缺口、局限和建议。界面约定和使用方式写入原 README，复用原控件/配色。

### 测试与 Review

Windows PowerShell Desktop **5.1** / RemoteSigned 下，SmokeTest、AnalyzerTest、GuiV4Test、PersistenceTest、ProcessActionsTest、PrivilegeSecurityTest、ServiceManagementTest、Milestone8Test 八个回归最终均退出 **0**。

新增测试覆盖 Finding 字段、Commit/RAM 独立、Pool 趋势、5/7/30/60 秒动态覆盖、长缺口、密集补采、重复时间、周期/时钟变化、PID 复用、同名不同路径、父 PID 复用、逻辑组缺失成员、null/零/非法/溢出计数器、Int64 精度、历史新字段往返及真实映像/父 PID 读取。GUI 使用真实控件验证冷启动、失效清空、选择身份、逻辑汇总及证据详情。

Review **Standards / Spec** 两轴首轮各发现一项 P2：新增采样分支缺少直接测试、枚举后首次身份查询前 PID 复用可能误关联。均修复并补测，两轴复核无剩余阻断项；后续性能优化亦经两轴复核。静态审阅不能替代实机验收。

测试自有隐藏 WinForms 窗口在 **1300×850、1020×690** 渲染，已查看截图，表头与详情未重叠。此项不是用户桌面端到端交互、真实 DPI 或多屏验收。frontend-design 静态 audit `--mode strict --no-write` 返回 0、无发现，其结果不替代 WinForms 运行验证。

### 性能证据

初轮同输入回放（618 进程、403 实例、完整进程窗口）基线分析均值 **2925.61 ms**、首版 M1 **4730.21 ms**；另 8 次真实采集均值 **1699.78 ms**、最大 **2131.51 ms**。首版存在默认 5 秒周期超时风险，没有记为性能通过。

定位后复用原 Analyzer 内紧凑 C# 时间槽/分段计算，消除原诊断每轮反复创建的 PowerShell 管道/排序对象。旧 double 中位数、半周期容差、85% 总体/分段覆盖、缺口阈值和报告文本保持不变。对照起始 SHA 的原函数，6 个周期 × 6 种输入（稳定、增长、缺口、抖动、稀疏、大整数），共 **36 组完整 JSON 报告逐字段一致**，新旧 AnalyzerTest 均通过。

最终独立复测在同一份 **590 进程、380 实例**输入上，两版均预填完整进程窗口、运行 8 轮并排除首轮：基线分析均值 **860.67 ms** / 最大 **948.86 ms**，最终 M1 **526.61 ms** / 最大 **663.13 ms**。这只证明该场景的分析开销；两轮负载和进程数不同，不能将初轮与末轮绝对时间当成同条件比较。也不代表 30 分钟真实持续采样、端到端 GUI 延迟或全部设备验收。

本地证据位于 `test-artifacts/v3-m1/`：smoke-reviewed.log、analyzer-optimized.log、GuiV4Test-optimized.log、PersistenceTest.log、ProcessActionsTest.log、PrivilegeSecurityTest.log、ServiceManagementTest.log、Milestone8Test-optimized.log、legacy-parity.log、performance-reviewed.json、performance-optimized.json、attribution-1020/1300.png。初轮失败及性能夹具类型加载错误日志保留，未改写为通过；测试产物不纳入源码提交。

**仍未验证与开放问题：**非管理员主机的管理员 ACL 分支为 SKIP；没有执行 PrivilegeInstallTest、受保护部署/UAC/卸载、真实管理操作、Windows 10、本轮长期 GUI/24 小时、真实故障/休眠/回拨或 DPI/多屏验收。旧版 <200 MiB 峰值和部分窗口覆盖不足仍然开放，本轮未放宽或宣称解决。WPR、Watchdog、Heap、WPAExporter、ActionGrant 未开放，M2–M7 仍需独立实现与验收。

## 2026-10-25 V3-M2：Protected Trace Architecture

冻结依据：v3 规格第 5、6、11–13、16 节及 V3-M2；起始本地提交 `1515f77`。本轮只实现 M2，在原有生产文件与测试中扩展，无新增代码模块，不修改普通监控/归因算法、采样周期或 ActionGrant 权限。VERSION 保持 0.0.9，新增安装清单架构标记；仅本地提交，不推送。

### 实现与安全边界

- TraceSession 完整字段、不可变身份、合法状态转换、全局 Journal revision CAS、追加 UTF-8 JSONL 与链式摘要；状态修改持有固定跨进程文件锁，持久化意图后才调用任务注册/删除。损坏、空文件、半条尾记录、重复 JSON 字段、未知 schema/状态及过期 revision 均拒绝。不用可编辑用户 JSON 作为授权凭证；只有受保护执行器的固定协议能进入控制路径。
- 停止、保存、清理、分析和活跃引用分别记录。Saved 不等于 Completed，未知结果不能重派发，待恢复会话阻断新会话及部署。M2 不配置实际 WPR Profile，因此预检查以 TraceBackendUnavailable 结束且不发生录制；Profile/WPR 归属、真实停止及 ETL 保存属于 M3，不能用本阶段数据模型测试代替。
- 固定 LocalSystem 任务使用受保护 DACL、固定系统 PS5.1 路径及安装执行器、固定参数，启动触发与每分钟重复，IgnoreNew、45 秒执行上限。核验动作、账户 SID、任务设置、完整 XML 指纹及安装文件哈希；健康挑战在 SYSTEM 完成扫描后回应，绑定 nonce、安装/启动身份、定义指纹、链头和截止时间。等待时释放全局锁，40 秒单调计时避免锁死与无限等待。
- Watchdog 在无工作时不追加心跳；未授权预检查中断可安全终结。检测已记录的过期/换启动会话后保留证据；实际 WPR 归属不可证明时进入 RecoveryRequired，不执行全局 cancel、进程 Kill 或未知命令。不得宣传当前已满足真实追踪的截止后两分钟停止验收。
- 安装/卸载独占部署租约，M2 服务执行器持共享租约；服务确认不占据 Watchdog 状态锁。安装目录及清单分步记录成功标记，失败时只恢复确实完成的步骤，所有旧文件及失败 staging 保留。首次迁移的注册前失败可在验证旧安装、日志与任务不存在后重试；注册结果未知不自动重试。退休日志可复用以重装。卸载归档产品文件，保留用户历史、策略、审计、Journal；数据 purge 当前拒绝。
- TraceRecovery 是安装内的固定管理员控制台入口，输出部署、任务、会话、服务恢复阻断及局限。仅对完整现存安装做新的 SYSTEM 健康核验后解除对应部署阻断；不清除未知会话或坏日志。日志不可读时生成阻断报告和人工指引。完整 GUI Wizard 属于 M7。

### Review 与修复

应用 Review 的 code-review（Standards / Spec 两轴），另做架构对抗审阅。用户明确选择不追加跨模型复核。

架构审阅促成：健康握手不持锁等待、跨记录状态约束、恢复时保留执行器/清单/任务依赖、有界任务运行及明确管理员威胁边界。哈希链不声称能抵御已取得管理员权限者回滚整个合法历史。

双轴首轮发现安装回滚窗口：旧目录已移走而新目录尚未就位、旧清单路径已赋值但备份尚未成功，均可能错误回滚。现按四个成功标记分别逆序恢复，并增加三个真实文件移动失败夹具。Spec 另发现首次迁移失败的恢复入口、卸载后重装和恢复报告阻断不一致，均补齐保留 Journal 的有限恢复路径及分项阻断字段。Standards 轴与 Spec 轴最终复核均无剩余提交阻断项；两轴结果分别记录，没有把静态通过等同于实机验收。

### 验证记录与尚未通过的发布门槛

普通权限 Windows PowerShell Desktop 5.1 / RemoteSigned 下，SmokeTest、PersistenceTest、AnalyzerTest、GuiV4Test、ProcessActionsTest、PrivilegeSecurityTest、ServiceManagementTest、Milestone8Test 八个回归最终均退出 0；日志保存在本地忽略目录 `test-artifacts/v3-m2/`。初轮 GuiV4Test 检测安装成功提示丢失 VERSION 显示约定，已恢复原版本驱动提示，未删除或放宽检查。初轮 Milestone8Test 另发现新中文注释的执行器缺少 BOM，已统一 UTF-8 BOM 后通过。

新增回归实际使用文件及独占句柄，覆盖：锁竞争/释放、服务部署租约互斥、一次活跃会话、CAS、身份变化、终态重放、Saved/cleanup/analysis 完成约束、时长边界、损坏/重复字段、健康 nonce/账户/启动/定义/链头绑定与过期/重放、预检查中断恢复、截止记录、重启身份变化、不重试未知归属、三处安装移动失败后原文件与清单保留。Task Scheduler COM 定义真实创建在内存内，核验动作、主体和运行时限变更拒绝；未注册任务。

PrivilegeInstallTest 已扩展真实 SYSTEM 握手、任务禁用时拒绝、非 SYSTEM 冒充拒绝、M3 门控和卸载重装；此脚本仅限全新 disposable Windows runner，本轮未在用户机器执行。管理员 ACL 分支为 SKIP；普通测试的 ACL/身份仅在自有夹具内模拟，不能称作权限实机验收通过。

**仍未验证：**真实 Program Files/ProgramData 安装、任务注册/DACL、SYSTEM 执行与开机触发、调度延迟、真实断电/进程崩溃/磁盘满、Windows 10/11 分别部署验收。第一次从旧版迁移前需关闭旧 GUI 和旧提权执行器，旧版不认识 M2 部署租约。任务注册后失败、实际状态未知或坏日志保持阻断，管理员需保留证据并修复可信状态，不能删除日志解锁。高级 WPR/Heap/ETL 功能保持禁用，不能宣布 Preview B 或 Stable v3。此前 <200 MiB 峰值与长时采样覆盖问题仍开放，本轮未重新验证或调整门槛。

Task Scheduler API 依据：[重复触发](https://learn.microsoft.com/en-us/windows/win32/taskschd/repeating-a-task)、[任务安全上下文](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、[任务安全描述符](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask-setsecuritydescriptor)。这些 API 文档不替代本项目的实机部署验收。

## 2026-10-25 V3-M3：WPR Core

冻结依据：规格第 5、6、8、11–14 节及 V3-M3；基线 `1955cb4`（M2）。修改原 PrivilegeSecurity、ElevatedExecutor、PrivilegeSecurityTest、PrivilegeInstallTest 及现有备注，没有新增代码模块。VERSION 保持 0.0.9；安装清单继续验证修改后的组件哈希。本地提交，不推送远程。

### M2 安全前置条件

本轮实际检查：PowerShell Desktop 5.1.22621.6133，Windows 11 build 22631；当前非管理员，受保护安装、Trace Journal、Watchdog 策略均不存在。先运行 M2 安全回归通过，但管理员 ACL 分支为 SKIP；既有 M2 记录同样没有真实 SYSTEM/开机/任务 DACL/Win10、11 验收。故 M3 总发布门、M2Accepted、MemoryAccepted、FileAccepted 全部固定关闭，任何实际 Start/Stop 在副作用前拒绝，没有用户设置、JSON 或专家模式绕过。普通监控和只读归因保持原行为。

### 实现范围

- 固定审核源码内 Profile：VirtualAlloc / Pool × Memory / File，1 MiB × 128 系统缓冲，绑定 XML SHA256。仅使用 System32 的已验证 Microsoft 签名 WPR，记录版本/摘要/签名身份，不接受用户可执行路径、Profile 或输出目录。启动后建立实际公共 ETW collector 身份；名称之外绑定 GUID、session handle、logger thread ID/创建时间、模式、临时路径、启动会话和启动意图。启动前后发现外部公共会话身份变化，保留 UnknownOutcome；不停止外部会话。
- 控制器确认后重新核验 M2 健康和资源；持共享部署租约与全局状态锁，写意图后一次派发。固定 `TraceStart/TraceStop/TraceArtifacts` 命令及对应参数分开验证。没有自由命令、全局 cancel/force、服务操作或进程 Kill。TraceStop 的手动请求须属于实际授权账户；没有把 GUI 用户 SID 从任意参数传入高权限路径。GUI 发起者安全绑定与界面整合尚属 M7，当前控制台确认者就是所有者。
- CreateProcessW 使用完整 ApplicationName、最小离线环境、受保护工作目录、隐藏窗口及 CREATE_BREAKAWAY_FROM_JOB；不支持脱离 Job 时拒绝，不回退到可能随 Watchdog 结束的子进程。高权限 CodeDom 编译临时文件位于受保护 workspace。ETW 查询要求管理员完整公共会话可见性；普通令牌查询得到空列表不被当作没有外部追踪。
- 独立 Watchdog 调用 M3 监督路径：归属核验后优先处理截止，资源不可读则保守请求一次受控停止。运行空间/可用 RAM 过低亦进入同一路径。Stop 意图、进程身份、停止观测时间和保存结果分开记录；停止/合并不阻塞 GUI，超过 180 秒的观察期限标记未知并保留恢复义务，不自动重试或 Kill。机器不可用时不承诺准时停止，健康环境截止后两分钟目标尚未实测。
- 三层容量独立计算：默认成品/相关诊断数据 8 GiB、工作空间 4 GiB、磁盘预留 2 GiB；启动 RAM 余量 1 GiB，监督时 Memory 工作量 ≥4 GiB、File 工作量 ≥2 GiB（余下一半留给合并）、磁盘剩余小于 2 GiB + max(1 GiB, 当前工作量)、或 RAM <512 MiB 请求受控停止；周期采样可能超出软预算，不能保证磁盘硬配额。阈值为工程初值，尚未冻结性能/容量验收。File Mode 用固定受保护临时目录，拒绝重解析点、不可读卷或不可信 ACL；继承自受保护父目录的 WPR 数据允许可信继承，不把它误判为可写控制文件。
- ETL 使用原生 OpenTrace/ProcessTrace 读取全部事件（消费时间上限 10 秒），再有界哈希（10 秒）；超时/损坏保持不可信并保留数据。事件/缓冲丢失降低 MeasurementQuality。实际有效 ETL 与大文件耗时未实测，这两个上限仍需兼容性校准，不能声称覆盖所有追踪文件。
- 保存前记录已校验字节数/哈希，移动后再提交 Ready。源/目标仅一个存在且身份吻合时可恢复；两处同时存在、缺失、哈希变化均保持阻断。停止确认后、首个 Artifact 意图前重启，也可在写者退出后重新核验已知输出完成保存。Saved 后失败保留 SaveState=Saved，不回退为未保存。M3 无 Heap 配置事务及分析器，CleanupState=NotRequired，AnalysisState=Unavailable。
- 受保护 ETL 仅对应所有者可读。默认 7 天到期后，在无引用和无冲突读句柄时归档到 `retained`，并处理移动后日志中断；遵守用户“不实际删除”要求，保留的字节仍计入预算。无自动上传/符号联网。人工导出只通过用户主动复制其可读文件，不为高权限执行器增加用户指定输出目录。普通历史配额不变。

### Review：Standards

基线固定为 `1955cb4`，审阅未提交差异。首轮发现资源读取失败造成监督中断，以及保存后失败使用陈旧 Session 导致非法状态回退；修复后增加期限与资源故障、Artifact Ready/Session Cleaning/Analyzing/Completed 日志边界测试。复核另发现 PowerShell 动态作用域验证变量未初始化、WPR 缺失时测试误报四次真实解析；均修复并测试。最终 Standards 复核无剩余阻断项。

### Review：Spec

独立首轮发现资源查询故障丢失截止处理，以及 ETL 移动后崩溃的保存事务无法恢复；随后发现首个 Artifact 意图前重启缺少恢复入口。现通过受保护保存意图、最新状态及真实文件核验恢复，未确认停止或写者仍存活时拒绝，不重派发 WPR。新增无 Artifact 的换启动会话恢复夹具。最终 Spec 复核无剩余阻断项。两轴结论均是代码审阅，不是实机发布验收。

### 验证与保留证据

Windows PowerShell Desktop 5.1 / STA / RemoteSigned：SmokeTest、AnalyzerTest、GuiV4Test、PersistenceTest、ProcessActionsTest、PrivilegeSecurityTest、ServiceManagementTest、Milestone8Test **八套全部退出 0**。新增测试运行真实 Journal、跨进程文件锁代码、文件移动/哈希、读句柄与原生无效 ETL 拒绝；WPR 启停、ACL、健康响应及有效 ETL 消费边界在夹具中模拟，不会录制本机。

新增覆盖：实际关闭的 Start/Stop/Recovery 门控、三层预算、固定模式/实例参数、Heap 拒绝、健康失败/取消、单活跃会话、身份替换/路径不可信/Profile 改写、未知 Start/Stop 不重试、期限优先于资源错误、资源不可读/超预算停止、停止与保存独立、四处保存日志故障、首次保存意图前重启、归档活跃引用/真实读句柄及移动后中断、保留字节仍计入预算。原 M2 锁/CAS/日志损坏、部署回滚及真实内存 COM 定义测试继续通过。

只读实机检查：WPR 文件版本 10.0.22621.5624，Microsoft 签名 Valid；四种固定 Profile 均由实际 `wpr -profiles <file>` 解析成功。原生 C# 适配器在 PS5.1 编译成功，损坏 ETL 由实际 OpenTrace 拒绝。**没有执行 WPR start/stop、SYSTEM 任务注册、安装/卸载或修改 Heap 配置。** PrivilegeInstallTest 增加真实安装后的 TraceStart 禁用验证，仅供 disposable runner；本轮未执行。

证据位于本地忽略目录 `test-artifacts/v3-m3/`：`prerequisite-status.json`、`m2-prerequisite.log`、`security-first.log`、`security-m3-first.log`、`security-recovery.log`、`security-final.log` 及八套同名日志。首次 CodeDom 缺少 System.dll 引用的编译失败已修复；没有降低测试标准。测试自有的 WprProfiles/WprCore 文件夹保留在 test-artifacts，不纳入源码提交。

### 仍关闭的发布关卡

待验证：真实受保护部署与 SYSTEM/计划任务健康、Windows 10/11 各版本 WPR Profile 支持、实际 collector 身份与外部追踪共存、Job breakaway、有效 ETL/事件丢失、Memory/File 实录/保存/合并、磁盘/内存压力、截止/崩溃/断电/休眠、调度延迟及性能开销。QueryAllTraces 仅返回调用者可访问的公共会话，不能作为所有私有 ETW 会话的完整盘点；不据此宣称无冲突。未知归属、无法确认停止或保存输入不完整时仍需管理员保留证据并独立修复，不能删除日志解锁。

所有上述验收通过前不修改源码内 release gate，不宣布 Preview B 或 Stable v3。此前 GUI 内存峰值和长时采样覆盖问题仍开放，M3 未修改相应阈值。Heap/M4、WPAExporter/M5、ActionGrant/M6 和 GUI/M7 不在本次范围。

## 2026-10-25 V3-M4：Heap Configuration Transactions

冻结依据：[v3 原文](https://docs.google.com/document/d/1GVln-oZKuIPkIR1C-Bh3JouyMhEO0z6X-dAscPpTHr4/edit)第 7、5–6、11–14、16、18 节及 M4；基线 `5daf938529836f2c0c489d6340946379257569ad`。只修改现有 PrivilegeSecurity、ElevatedExecutor、PrivilegeSecurityTest、PrivilegeInstallTest 及两份备注；无新增模块、无数据删除，VERSION 保持 0.0.9。仅本地提交，不推送。

### M2/M3 前置核验

本机 Windows 11 build 22631，普通令牌；Program Files 受保护安装、Trace Journal、Watchdog policy 均不存在。先运行未修改前的 Windows PowerShell 5.1 安全回归，退出 0，管理员 ACL 分支跳过。M2 的真实 SYSTEM/任务 DACL/启动触发及 Win10/11 验收仍未完成，M3 的真实 WPR 所有权/录制/保存/资源保护同样未验收。原 WPR 发布门保持关闭，新增 Heap Enabled、ConfigurationAccepted、RecoveryAccepted 全为 false；执行器和注册表写入入口均在副作用前拒绝，无法用 JSON、参数或专家选项绕过。

### 实现与安全边界

- Heap 作为固定 TraceStart 类型，独立校验 HeapImagePath 参数归属；没有任意注册表路径、自由命令、目标进程启动/重启/Kill 或 Snapshot。固定 HeapEventCollector/HeapEventProvider 的 Memory/File Profile 仍绑定 SHA256、命名实例、ETW GUID/handle/线程创建时间、预算、期限和实际文件路径，Heap 用户 collector 与原 system collector 模式分别核验。
- 目标身份从同一受限共享文件句柄读取 PE 与 SHA256；本地绝对路径、文件及父级不得为重解析点。格式检查限定为原生 x64 PE 和受限 `.exe` 基名；x86/托管、IFEO Filter/子键明确拒绝。打包原生程序等具体类型仍未验收，Heap 总门保持关闭，不声称全程序类型支持。配置按映像名作用于所有同名新实例，跨路径/用户；确认前明确显示范围、目标路径/摘要，以及用户可能需要自行重启已有实例。工具不会代为重启。
- 事务包含 TransactionId、TargetImageIdentity、OriginalConfig、ExpectedModifiedConfig、ConfigOwner、ChangeUtc、CurrentConfig、RestoreState、ConflictDetected 和 revision。复用受保护哈希链 Journal、追加 Flush、全局文件锁/CAS；未知结构、非法转换、替换原值/目标或重放均拒绝。ChangeUtc 是写前意图的 UTC；Applied 另由读后核验成立，不用意图时间宣称实际已经修改。
- 唯一可写对象是 Registry64/HKLM 固定 IFEO 映像下的 TracingFlags。核验注册表所有者、有效 ACL 和父级替换权限；CREATOR OWNER 按已核验实际所有者处理，继承专用 ACE 不误当当前键授权。原值缺失或 DWORD 0 可按授权设 1；原值 1 不写入并记 External；其他位/类型/读取失败拒绝。旁侧值和子键指纹用于发现外部变化，写前比较并在写后重新核验。
- 每次实际写入必须有已 Flush 的 Intent/Restoring，不能从会话名推断修改权。恢复只复原原来的 TracingFlags 值/缺失状态，不恢复整个 IFEO；新建空键保留，其他值/键不删除。外部改动进入 Conflict，不盲目覆盖；管理员须先在系统中恢复原值，显式恢复入口再核验并记账。管理员不受本工具锁约束，注册表 API 不提供与外部管理工具之间的原子 CAS；本实现采用紧邻写入的比较/读后核验，不宣称能抵御恶意管理员竞态。
- CleanupPending 和 Conflict 保留恢复义务，禁止 Completed、升级、卸载与部署 Ready。停止确认、保存状态、Heap 恢复结果独立，ETL 失败后仍处理可证明安全的配置恢复。未知 WPR 启动/停止或活跃写者不触发猜测性注册表写入，换启动会话重新核验 ETW；写入已完成但记账失败时只补记真实结果。未知恢复结果不自动重写；`RECOVER HEAP CONFIG` 显式重新读取后，才允许对尚需恢复的已拥有值尝试恢复。所有修改/恢复路径同受关闭的 Heap 发布门限制。
- 配置准备失败且 WPR 未派发时，使用不可变 PreStartResolution 辅助结果消除已经解决的恢复义务，保留 RecoveryRequired 的异常历史，不假称 Completed。要求完整 Journal、事务已 Restored 或严格证明不存在写前意图、无启动/停止/保存身份及 Artifact、成功枚举确认两种派发标记缺失、实际 ETW 查询成功且无该实例；读取失败和未知派发继续阻断。终结后禁止记录重放、重开或再次派发，不能用该结果解除其他会话的事务。

### Review 与验证

首轮 PS5.1 安全回归通过，新增 M4 场景覆盖原值缺失/0/兼容 1/未知位/错误类型/Filter、读取失败/取消/目标变化、写前意图失败、修改前后异常、恢复写入前后及恢复记账中断、外部配置/旁侧变化、重启、未知活跃追踪，以及保存失败与配置恢复的独立结果。真实 Journal、文件锁、哈希与 ETL 保存路径执行，注册表/WPR/ACL/健康响应边界使用测试替身。

### Review：Standards

固定基线 `5daf938`，独立审阅未提交差异。首轮发现配置修复成功后会话仍停留 CleanupPending，必须等额外 Watchdog 扫描才能进入保存恢复。现显式转 RecoveryRequired，再由已有保存恢复重新核验 ETL；新增不依赖 Watchdog 的恢复流程，断言 Completed 与 Assert-MiTraceQuiescent。复核无剩余阻断项，用户的既有模块、中文注释、UTF-8、行为测试与本地提交边界均保留。

### Review：Spec

独立首轮发现准备失败但未派发 WPR 的已恢复会话永久阻断部署。现通过上述 PreStartResolution 安全终结这类义务，并校验事务双向绑定和 NoWriteIntent/Restored 的精确对应关系。增加 Intent/Applied/写入前后、授权后目标/配置延迟读取失败的恢复闭环，以及派发标记/ETW/路径不可读/伪造结果保持阻断的测试。复核无剩余 actionable finding。两轴均为静态审阅，不等同于实机验收。

最终 Windows PowerShell Desktop 5.1.22621.6133 / STA / RemoteSigned：SmokeTest、PersistenceTest、AnalyzerTest、GuiV4Test、ProcessActionsTest、PrivilegeSecurityTest、ServiceManagementTest、Milestone8Test **八套全部退出 0**。原生只读 PE/摘要、固定注册表缺失键查询、六种 Profile 的实际 WPR 语法解析通过；实际发布门、注册表写入与恢复门的拒绝测试通过。管理员 ACL 分支仍跳过；真实 IFEO 写入/恢复及 WPR 启停由替身代替，不计作发布验收。

中途新增“路径不可读”故障夹具触发全局 Journal ACL 拒绝，测试最初错误地期待返回状态，已改为断言拒绝且恢复读取后义务仍在；没有放宽生产检查。最终在全部修复后重新运行八套回归。受影响 PowerShell 文件保持 UTF-8 BOM，`git diff --check` 通过，历史/允许名单及普通监控逻辑未修改。

证据保留于本地忽略目录 `test-artifacts/v3-m4/`：前置检查、安全回归、六种 Profile 的只读语法验证及完整回归日志。没有在本机注册 SYSTEM 任务、安装/卸载、启停 WPR、启用 IFEO 或重启目标。PrivilegeInstallTest 仅新增 disposable runner 的 Heap 禁用验证，本轮不执行该安装测试。

API 依据：[Microsoft Heap 录制与 TracingFlags](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/recording-for-heap-analysis)、[HeapEventProvider](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/heapeventprovider)。文档用于确认配置/Profile 契约，不能替代 Windows 实机恢复验收。

### 仍关闭的验收关卡

M2/M3 既有实机关卡全部保留。M4 还需隔离 Windows 10/11 的真实 IFEO 权限/修改/兼容复用/外部冲突、进程自行重启后的 Heap 生效与有效 ETL、Memory/File 压力、Controller/Watchdog/机器重启与真实恢复故障验收。`[NEEDS CLARIFICATION]` 支持的具体 Windows/WPR/程序类型矩阵与性能参数仍需按冻结规格第 20 节校准，不重新开放 Q1–Q31 决策。上述验收前不开放 Heap，不宣布 Preview C 或 Stable v3；M5/M6/M7 与旧 GUI 内存/采样覆盖问题没有在本次宣称完成。

## 2026-10-25 V3-M5：Automated Attribution Export

冻结依据：[v3 原文](https://docs.google.com/document/d/1GVln-oZKuIPkIR1C-Bh3JouyMhEO0z6X-dAscPpTHr4/edit)第 9、5–8、11–14、16、18 节及 M5；基线 `f40506c7522e3ef4ea65ecfa1e98d016034e08bb`。扩展原 Analyzer、PrivilegeSecurity、ElevatedExecutor、Installer 与原有测试/备注，无新增生产模块。VERSION 仍为 0.0.9；仅本地提交，不推送。

### M2–M4 安全前置条件

本轮 PS Desktop 5.1.22621.6133、Windows 11 build 22631、普通令牌。受保护安装、Journal、Watchdog policy 均不存在；两个固定 ADK WPAExporter 路径均不存在。修改前 M2–M4 安全回归退出 0，但管理员 ACL 分支跳过。M2 SYSTEM/任务/Win10、11、M3 实录/ETL/资源以及 M4 实际 IFEO/故障恢复验收没有完成。因此原门控不变；新增 M5 Enabled/OfflineAccepted/OnlineAccepted/NormalizationAccepted 全部 false，运行适配器和准备描述均在副作用前拒绝。

### 实现与信任边界

- 高权限固定命令 TraceExportPrepare 仅接受 ArtifactId；完整安装/新健康检查、已确认停止/保存/Heap 清理、Artifact 所属账户及 ETL 再消费/哈希/时间范围全部核验后，先向原 Journal 提交不可变 ExportDescriptor，再写对应账户可读的固定描述。损坏/部分描述保留并拒绝覆盖，不猜测重建。描述中的 AnalyzerSha256 记录准备者身份；后续受保护升级可按同一 Schema 读取历史数据，不要求执行旧代码。
- 普通用户函数 Invoke-MiAttributionExport 只接受 ArtifactId/OnlineSymbols，拒绝管理员与 SYSTEM；只从已安装、ACL 受保护的组件运行。受保护执行器与 Watchdog 不启动 WPAExporter，也不读取或执行用户 CSV/结果。用户输出是 UserOwnedDiagnosticOnly，不回写受保护 Session 历史结果、不生成 ActionGrant，不关联当前 PID。M7 再接 GUI 和异步调用。
- 部署锁文件增加 Users 只读权限，写入仍限管理员/SYSTEM；导出持共享读取租约，独占升级/卸载不能并行。ETL 读句柄拒绝写入/删除共享，保留策略不能移动正在分析的 ETL。崩溃后 OS 释放句柄；子进程在挂入本次 Job 后才恢复运行，Job 随父进程关闭，仅限制/结束它创建的导出器，不触及诊断目标进程。
- 候选程序只来自两个固定 ADK 路径，核验 Microsoft 签名、摘要/版本与可信目录；不使用 PATH 查找或用户插件/命令。Profile 从源码生成，移除外部 FileReference/符号/插件配置。VirtualAlloc/Heap 的 Graph/Column GUID 从 Microsoft MSO-Scripts 实际 Profile 核对；Pool GUID 仅作为 Microsoft HOBL 中的事实索引，未复制该目录专有 XML。**当前 AcceptedVersions/Headers 为空，字节单位未确认；任何实际版本均 AnalysisUnavailable，不把候选 XML 或合成 CSV 当作实际表支持。**
- 默认不带 -symbols，子进程最小环境覆盖非空本地 _NT_SYMBOL_PATH、_NT_ALT_SYMBOL_PATH 与本次 _NT_SYMCACHE_PATH，避免空值回落在线默认。OnlineSymbols 必须独立源码验收门通过，并每次显示分析 ID、下载用途、唯一 Microsoft HTTPS 符号服务器和专属缓存，经准确输入才用于该子进程；取消继续离线，不保存可复用授权。已确认子进程退出且返回已知失败时可另存无符号结果，未知/超时不重试。
- 子进程 Job 初始限制：1 GiB Job 内存、一个进程、120 秒；工作区含 CSV/缓存每次 64 MiB，磁盘预留 2 GiB。全部用户导出数据继续计入诊断根目录 8 GiB 软预算，拒绝重解析点、无法枚举的目录及预算读取失败；周期检查不是文件系统硬配额。逐 Finding 按实际压缩 UTF-8 累计限制 16 MiB；最终 JSON 写入前再次计量工作区、全局和磁盘余量，超限返回空 Findings 的 AnalysisPartial，不落盘超大结果，不删除源 CSV。多账户目录无法按当前令牌读取时拒绝分析，不把不可见数据当作零。
- 固定 CSV 契约仅在实际版本/单位接受后使用。严格字段数/唯一表头、整数单位、行/字段/文件上限；拒绝重复范围、汇总行、非法引号/UTF-8/控制字符/公式、小数/负数/溢出。Finding 保留 Int64、来源、实际时间范围、SourceScope、事件丢失、符号状态、局限和下一步；分配表值不当作当前 RAM/保留量/增长。GrowthBytes 与 ProcessInstanceId 为 null，不从进程标签/PID 猜实例。缺表/空表/解析失败为 AnalysisPartial；缺失/不支持工具为 AnalysisUnavailable，ETL 保留并输出普通权限 WPA 手动指引。符号成功不能由退出码证明，缺符号不等于无异常。

### 审阅与验证

GrillMe 标记已按其仓库事实查证工作流核对 Profile/符号路径来源；产品决策沿用冻结文档，没有重新开启 Q1–Q31 或新增 ADR/代码模块。随后按用户要求使用 Review 对固定基线差异进行 Standards/Spec 独立审阅。

### Review：Standards

固定基线 `f40506c`。首轮发现小 CSV 的逐行说明可能放大归一化 JSON，绕过导出器退出前的工作区检查。现按真实序列化字节限制 Findings，并在最终 CreateNew/Flush 前重新复核存储余量；新增归一化放大、结果写入前预算耗尽回归。最终复核无剩余提交阻断项，未新增生产模块，保留中文关键注释、UTF-8 和原有安全阈值。

### Review：Spec

独立审阅确认同一预算缺口，修复后无剩余可确认缺陷。共享部署租约、ETL 读句柄、保留互斥、单次符号授权、未知结果不重派发及降级路径符合冻结要求；没有范围扩张。两轴均属于静态代码与测试审阅，不替代真实 WPAExporter、网络或 Windows 验收。

### 验证与保留证据

AnalyzerTest 的真实 CSV/UTF-8/引号/整数精度、错误拒绝和普通工作流程通过；ETL/工具/ACL/已接受版本为明确测试替身。专用 C# 导出器适配器在 PS5.1 编译通过，普通令牌真实创建两次本次拥有的隐藏 System32 cmd 子进程，经挂入 Job 后执行固定 exit，准确得到 0/7；该探针只验证启动与已知退出码，不计作真实 WPAExporter、Job 故障、压力或网络验收。

全部修复后，在 Windows PowerShell Desktop 5.1.22621.6133 / STA / RemoteSigned 最终重跑 SmokeTest、PersistenceTest、AnalyzerTest、GuiV4Test、ProcessActionsTest、PrivilegeSecurityTest、ServiceManagementTest、Milestone8Test，**八套全部退出 0**。原有六种 WPR Profile 的只读语法验证与实际发布门拒绝继续通过，管理员 ACL 夹具仍跳过。七个修改的 PowerShell 文件均保留 UTF-8 BOM，九个源码/文档严格 UTF-8 解码与 `git diff --check` 通过，没有降低既有阈值或跳过新增行为断言。完整结果为 `final-regression-results.json` 与 `final-*.log`。

前置与后续日志保留在本地忽略目录 `test-artifacts/v3-m5/`，不随源码提交。PrivilegeInstallTest 只增加 disposable runner 的 M5 禁用校验，本机不执行安装。没有注册 SYSTEM 任务、启停 WPR、修改 IFEO、安装 ADK 或下载符号。

### 仍关闭的验收关卡

M2–M4 全部真实安全关卡继续保留。M5 还需在隔离 Windows 10/11 与明确 ADK/WPAExporter 版本中，验收最小 Profile、CSV 表名/表头/字节单位/层级/聚合语义、实际有效 ETL/事件丢失、普通用户 ACL/共享租约、Job/崩溃/超时/磁盘/内存压力、离线无符号流量以及单次服务器/缓存/失败降级。`[NEEDS CLARIFICATION]` 实际版本/表/单位矩阵和资源阈值需按冻结规格第 20 节校准；不能臆造接受版本或放宽检查。未验收保持禁用，不宣布高级诊断或 Stable v3 已可用。M6/M7 与既有 GUI 内存/采样覆盖问题不在本次完成范围。

API/事实来源：[WPAExporter](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/exporter)、[符号路径与默认回落](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/loading-symbols)、[VirtualAlloc Profile](https://github.com/microsoft/MSO-Scripts/blob/main/src/WPAP/VirtualAlloc.wpaProfile)、[Heap Profile](https://github.com/microsoft/MSO-Scripts/blob/main/src/WPAP/Heap.wpaProfile)、[Pool 事实索引](https://github.com/microsoft/HOBL/blob/f183bc4166826c7b617b231b79db6d9f9cd08589/utilities/proprietary/ParsePowerLight/Catalog/WpaRuleMatchExporter.wpaProfile)。文档/源码用于核对契约，不能替代上述实机验收。

API 依据：[WPR 命令与模式](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options)、[命名实例](https://devblogs.microsoft.com/performance-diagnostics/controlling-the-event-session-name-with-the-instance-name/)、[QueryAllTraces 可见性](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-queryalltracesw)、[ETW 会话属性](https://learn.microsoft.com/en-us/windows/desktop/ETW/event-trace-properties)、[OpenTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew)、[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)、[Job breakaway / 隐藏进程标志](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)。文档只证明 API 契约，不替代上述实机验收。
