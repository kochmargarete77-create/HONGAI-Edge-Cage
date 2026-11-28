HONG AI 客户端只读观测包｜Windows

用途
供客户智能体在本机采集一段短时、被动的运行概况，以便判断问题发生时应用是否存在、资源是否变化、Claude 进程是否有既有 TCP 连接。它不是网络评分、IP 信誉检测、网络修复、防封号保证或安装器；不代替真实业务验收。

默认行为
运行 5 分钟，每 10 秒采样一次。可配置观察窗口最多 1800 秒、180 个样本，用单调 Stopwatch 控制，UTC 只作时间线；Windows 本地进程/连接表 API 若阻塞可能延后返回，本工具不为严格卡墙钟时间而强杀进程。间隔较短时，达到 180 样本会提前结束。输出只追加到本次新建的 observation.ndjson，NDJSON 硬上限 5 MiB；每行另限 64 KiB，不为腾空间删除任何客户文件。每次使用新的 session-随机ID 文件夹，不复用上次文件。

采集范围
1. 固定目标名称集合：Claude、cowork/cowork-svc、Clash/Clash Verge/ClashX、mihomo/verge-mihomo、ToDesk 的已知进程名称；输出只显示 claude、cowork、mihomo、clash、todesk 五个角色的进程数、CPU 增量和内存工作集聚合。角色来自名称启发式，不是应用签名或可信身份验证。CPU 基线只用本次内存中的 PID+进程启动时间匹配，避免 PID 重用；这些值绝不写出。
2. 仅目标 Claude 进程已经存在的 TCP 连接表：状态、IPv4/IPv6、远端端口类别 443/80/other、地址类别 public/private/loopback/linklocal/reserved_or_benchmark/other 的计数。IPv4-mapped IPv6 按实际映射地址分类；TEST-NET、100.64/10 CGNAT 与 198.18/15 基准/fake-IP 段归保留类，不误报公网泄漏。读取内核现有表，不建立测试连接，不解析域名，不抓包、不读通信正文。
3. UTC 采样时间、会话内相对时间、运行时报告的 OS 数字版本与架构。版本可能受 Windows 兼容层影响，不据此猜测正式产品版本名称。
4. 权限或能力不足明确写 NOT_OBSERVED/PARTIAL 和固定错误代码；真正查到为空才是 EMPTY。首个样本没有 CPU 基线，不把它假装成 0 使用率。新进程或无法读取启动时间的进程不贡献 CPU 增量，内存仍可单独记录覆盖率。

不采集或不执行
不读取或遍历 Claude 的配置、登录目录、用户资料、Cookie、Token、凭据、聊天和文档；不读取命令行、程序完整路径、硬件序列号。报告不含 PID、真实 IP、主机名、机器名或用户名。PID/地址只在内存中用于筛选和分类，写出前丢弃。
不更改代理、系统 DNS、TUN、路由、防火墙、系统时间或登录态；不提权、不装驱动、不安装依赖、不停止任何进程、不重启、不向外部网站或服务器发请求。只新增指定输出目录中的本次观测文件，不自动回传。

客户智能体执行
1. 将 Collect-ReadOnly-Windows.ps1 放在已批准的 D/E 数据盘位置。使用客户已经授予的普通用户权限，不为采集失败升级权限。
2. 选一个本地 D/E 盘的专用目录，例如 D:\HONGAI-Observation。脚本拒绝系统盘、根目录、网络映射盘以及路径中的目录联接/符号链接；同用户恶意并发换路径不在本只读工具的系统安全边界内。
3. 在现有 PowerShell 中运行，保留系统原有执行策略，不使用绕过安全策略的参数：

   & '.\Collect-ReadOnly-Windows.ps1' -OutputDirectory 'D:\HONGAI-Observation'

   可选缩短本次观察时间：
   & '.\Collect-ReadOnly-Windows.ps1' -OutputDirectory 'D:\HONGAI-Observation' -DurationSeconds 120 -IntervalSeconds 10

4. 观察期间按原来的方式使用客户端。不要为了这个采集器切节点、修改网络、清登录态或重启远控。结束后会返回 session 的相对文件夹名；报告在指定目录的该文件夹中，仅把 observation.ndjson 交给服务人员即可。
5. 没有检测到 Claude 进程、没有 TCP 权限、固定进程名未覆盖某个新版本或采样时应用恰好退出，均会导致观测不完整。NOT_OBSERVED 不能当作“没有问题”或“确认泄漏”。单次最多取 20000 条现有目标连接，达到此上限标 PARTIAL，不为追求全量而放大内存。工具不观察 UDP、QUIC、代理隧道里的真实业务目的地、IPv6 路由策略或所有子进程；地址类别是粗分类，结果不等于实际出口 IP、归属地、账号状态或故障因果。

隐私与停止
Ctrl+C 可以结束本次采集；已写入的行保留。强制中断时最后一行可能不完整，分析方应标记截断，不补造样本。报告会透露短时应用角色是否在运行及资源/连接数量，仍应按客户服务资料管理。只有本次随机 session ID，无跨会话机器跟踪 ID。

合成自检：不采集本机信息
脚本被 dot-source 或传 -FunctionsOnly 时只加载函数，不自动运行观测。

   . '.\Collect-ReadOnly-Windows.ps1' -FunctionsOnly
   Test-HongaiObservationHelpers

此自检只处理内置的合成进程、地址和计数，不查询实际进程、TCP、操作系统资料或用户数据，也不创建采集报告。正式采集需要另外明确调用脚本并填写输出目录。

交付边界
本包仅完成合成 fixture 自检和脚本解析，不冒称在真实客户网络、真实账号、真实 Claude 版本或各种权限配置上已经完成验收。若本机策略禁止运行脚本，记录为权限条件未满足，由客户按组织流程处理，不关闭防护或降低策略。

跨端日志协议
schema 固定 hongai.passive-observation.v1，每行 JSON。recordType 为 header/sample/footer，sessionId 为 32 位随机十六进制，utcISO 为 UTC 时间。header 含 os、collector、limits；sample 含 sampleIndex、elapsedSeconds、processes.roles 五角色对象及 tcp.categories 分类计数；footer 含 samplesWritten、completionCode、elapsedSeconds。Windows CPU 指标为 cpuDeltaSeconds，Mac 可另提供 cpuPercent，不能直接混为同一指标；内存统一 workingSetBytesTotal 字节。
