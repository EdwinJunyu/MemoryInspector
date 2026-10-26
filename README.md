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

实际 WPR、Heap 配置、WPAExporter、ActionGrant 尚未开放；Watchdog 的 M2 架构见下文。开发验证与已知限制见 [项目验收备注](docs/M8-ACCEPTANCE.md)。

## V3-M2 — Protected Trace Architecture（开发阶段，实机部署验收待完成）

在原 PrivilegeSecurity / ElevatedExecutor / Installer / Uninstaller 内实现受保护 TraceSession、Journal、固定 Controller 命令、SYSTEM Watchdog 和恢复入口，没有新增生产模块。VERSION 仍为 0.0.9；安装清单另有 `TraceArchitectureVersion=1`，用于区分旧安装与 M2 架构，不放宽旧版精确版本信任。

- Journal 位于产品 ProgramData 的 `trace` 受保护目录，采用 UTF-8、SchemaVersion、连续 revision、哈希链及追加写入/Flush。全局独占文件锁跨进程协调；缺失、截断、重复字段、未知结构或非法状态转换拒绝继续，不自动补尾。哈希链用于发现损坏，ACL 才是普通用户写入边界；不声称抵御管理员回滚整份合法历史。
- 会话绑定身份和启动会话，时长使用秒（默认 300、范围 300–1800）。停止、保存、配置清理及分析分别记录；Saved、CleanupPending、UnknownOutcome 都不能冒充 Completed。未完成会话、有效引用或服务恢复记录阻断升级/卸载。
- 安装器注册固定 `\MemoryInspector.TraceWatchdog`：LocalSystem、受保护任务 DACL、固定 Windows PowerShell 5.1/执行器/参数、启动触发与每分钟重复、IgnoreNew、单次运行上限 45 秒。健康检查写入最长约 40 秒的挑战，释放锁后等待 SYSTEM 扫描响应，再核验 nonce、启动身份、安装身份、任务指纹及 Journal 链头。任务存在不等于可用。
- M2 预检查仅记录固定 VirtualAlloc / Memory / 5 分钟请求，明确返回 `TraceBackendUnavailable`，不运行 WPR。Watchdog 可结束尚未授权的中断预检查；对已录制但无法建立实际归属的状态，只记录截止/重启证据并进入 RecoveryRequired，不停止未知追踪、不重复未知操作。M3 才能接入实际 WPR 所有权与停止/保存适配器。
- 安装保留旧目录、旧清单和失败 staging。注册前失败按每一步成功状态恢复；注册后结果不明时保留匹配的执行器/清单/Journal。已退休日志支持安全重装。卸载只移除已核验的固定任务，并把程序文件归档到产品 ProgramData 的 `retired`；历史、审计和策略保留，`-PurgeProtectedData` 当前拒绝。
- 服务管理持有共享部署租约，安装/卸载持有独占租约；长时间人工确认不会占住 Watchdog 的状态锁。旧版首次迁移前仍须关闭旧 GUI、结束旧版提权操作，旧执行器没有 M2 租约协议。

仅在隔离 Windows 环境检查源码后运行安装器。安装后的管理员 Windows PowerShell 5.1 恢复入口为：

```powershell
$executor = Join-Path $env:ProgramW6432 'MemoryInspector\ElevatedExecutor.ps1'
& $executor -Operation TraceRecovery -RequestId ([guid]::NewGuid().ToString('N'))
```

默认输出诊断报告；输入 `VERIFY DEPLOYMENT` 只重新核验已有完整安装和新的 SYSTEM 响应，成功后解除对应部署阻断。它不能删除日志、清除未知会话、重建被篡改任务或跳过配置恢复。初次迁移在任务注册前失败且已核验回滚时，可重跑安装器，保留并复用原 Journal。日志损坏或实际 WPR 归属不可证明时只提供人工指引，继续阻断。完整 GUI Recovery Wizard 整合属于 M7。

本轮只执行普通权限回归、真实文件故障夹具及内存 COM 定义检查，**未在本机安装 SYSTEM 任务**。真实安装/健康响应/禁用任务拒绝/卸载重装已加入原 PrivilegeInstallTest，仍需隔离环境执行；Windows 10/11 启动、调度延迟和权限实测未完成，因此不能据此开放高级追踪或宣布 Preview B / Stable v3。

## V3-M3 — WPR Core（代码完成，录制发布门关闭）

按冻结规格在原 PrivilegeSecurity / ElevatedExecutor 内接入固定 VirtualAlloc、Pool Profile、默认 Memory / 可选 File Mode、独立停止/保存、受保护 ETL 目录与恢复事务。**本机 M2 前置条件未通过：没有受保护安装、Journal 或 Watchdog 策略，当前令牌不是管理员。** M2 的真实 SYSTEM、任务 DACL、启动触发与 Windows 10/11 验收也未完成。因此 `Get-MiWprReleaseStatus` 的 M2/Memory/File 验收标志及总开关固定为 false，不提供配置绕过；实际追踪尚不能使用，不能发布 Preview B。

- `TraceStart` 只接受 VirtualAlloc/Pool、Memory/File、300–1800 秒；默认 300 秒，独立显示并确认本次请求。只有发布门、完整安装、实际 SYSTEM 健康响应、公共 ETW 状态、路径与三层预算全部通过才有启动资格。GUI 高级追踪接入留待 M7。
- 归属绑定启动会话、授权、固定 Profile/程序身份、启动意图和 ETW GUID/handle/logger thread 创建时间等证据。停止只能作用于已绑定实例；不存在全局 cancel、force、任意路径/命令或进程 Kill。仅名称匹配、结果未知、线程/程序身份变化均不派发停止。QueryAllTraces 不声称能枚举所有私有会话，实际共存能力须实机验收。
- WPR 隐藏子进程使用固定完整路径和最小环境，独立于 GUI。停止/合并异步进行，Watchdog 观察精确子进程身份；通过 Job breakaway 避免被任务运行时限一起结束，不支持脱离时拒绝。停止确认、ETL 校验与保存、清理和分析各自记录，不把派发成功当作保存完成。
- 当前工程预算：128 MiB Profile 缓冲、4 GiB 工作预算、2 GiB 磁盘预留、8 GiB ETL/诊断存储预算；这些工作阈值需在目标设备校准，不是文件系统硬上限。File 录制占用达到工作预算一半即请求停止，为合并保留空间。资源读取失败先重新核验归属再请求一次停止，期限判断优先。File Mode 的实际临时路径、ACL/重解析点及磁盘卷必须可信。
- ETL 在产品 ProgramData 的固定 `diagnostics/<OwnerSid>/<ArtifactId>.etl` 保存，仅授予对应授权用户只读访问；不联网、不自动上传、不生成联网符号。`TraceArtifacts` 是受保护目录的只读清单入口。M3 无自动分析器，完成后的 AnalysisState 为 Unavailable；有效 ETL 的完整消费校验和事件丢失信息独立于 WPAExporter。
- 默认 7 天到期；遵守本项目“不实际删除”要求，自动清理将已核验、无活跃引用/读句柄的 ETL 移入同一受保护所有者目录下的 `retained`，仍计入 8 GiB 预算，不报告释放空间。普通监控历史不受此配额影响。用户可明确使用普通文件操作导出自己可读的副本，该副本不受本工具保留策略管理。
- 固定 `TraceRecovery` 报告新增门控和 Artifact 状态；`RECOVER SAVED ARTIFACTS` 仅在发布验收通过后恢复已经确认停止、写者退出的已知保存事务。记录前后崩溃均重新核验实际文件，绝不补发未知 Start/Stop。未完成会话、保存/归档事务和引用继续阻断安装/卸载。

本轮四种 Profile 已通过本机 WPR 的只读语法解析，八个 PS5.1 回归与 Review 双轴复核通过。实际录制/停止、有效 ETL、SYSTEM 子进程 Job breakaway、资源压力、外部追踪共存和 Windows 10/11 验收均未完成，**不把模拟测试等同于发布验收**。详细记录见 [M3 项目备注](docs/M8-ACCEPTANCE.md#2026-10-25-v3-m3wpr-core)。VERSION 仍为 0.0.9，仅本地提交，不推送。

## V3-M4 — Heap Configuration Transactions（开发实现，发布门关闭）

按冻结规格第 7 节及 M4，在现有安全模块、执行器和测试内实现 Heap 专项事务，没有新增生产模块。M2/M3 的本机复核仍未通过受保护部署/SYSTEM/Win10、11 验收，因此 WPR 与独立 Heap 发布门全部保持 false；没有设置、参数或 Journal 标志可以解锁。VERSION 保持 0.0.9。

- Heap 请求绑定本地原生 x64 PE 文件的路径、映像名与 SHA256；目前只接受限定的普通 `.exe` 名称，其他架构、托管程序、IFEO Filter/子键等兼容性未核验时拒绝。IFEO 作用于所有同名新进程，包含其他路径/用户；控制台确认前显示该范围和目标摘要。已有实例可能需要用户自行重启，工具不启动、重启或终止目标，不增加 Heap Snapshot。
- 固定 Registry64 IFEO 的 `TracingFlags` 是唯一写入范围。读取失败、类型未知或未确认的配置位均拒绝；原值为 DWORD 1 时复用且不写入，缺失/0 才建立修改事务。记录原值、预期值、目标身份、所有者、UTC、实际读取值、恢复状态及冲突，复用受保护追加 Journal、全局锁和 revision 检查。修改前必须提交并 Flush 意图，写后核验。
- 停止、ETL 保存与 Heap 恢复保持独立。恢复只处理本工具拥有的值，旁侧 IFEO 值/子键发生变化也会报告冲突，不覆盖外部修改。原先不存在的值只移除该值，新建空键保留。恢复失败进入 CleanupPending，阻断完成/升级/卸载；已知写入结果丢失时重新读取，不重复 Enable，不自动重试未知恢复写入。
- Watchdog 在可证明追踪和写者已结束后处理配置义务；换启动会话重新核验实际 ETW 和配置。未知归属或仍有写者时拒绝写入。`TraceRecovery` 增加 `RECOVER HEAP CONFIG`，只处理已有受保护事务；发生冲突须先由管理员恢复原值，再通过只读核验记账，不能强制覆盖。此入口同样受未验收发布门限制。
- 配置准备失败但尚未派发 WPR 时，恢复入口会核验完整 Journal、已恢复配置/无写前意图、成功枚举所得的派发标记缺失和实际 ETW 状态。证明成立后记录不可变的 `PreStartResolution`，保留异常历史并解除恢复义务；不声称曾经录制或完成 ETL。任何证据未知时继续阻断。

开发回归使用真实 Journal/文件故障夹具，注册表修改与 WPR 启停使用测试替身。实际 IFEO 启用/恢复、有效 Heap ETL、SYSTEM、故障/重启与 Windows 10/11 兼容性和性能均未验收，不能宣布 Preview C / Stable v3。详见 [M4 项目备注](docs/M8-ACCEPTANCE.md#2026-10-25-v3-m4heap-configuration-transactions)。

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
