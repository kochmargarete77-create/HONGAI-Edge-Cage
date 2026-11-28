HONG AI｜macOS 被动只读观测器

用途
在客户自愿正常使用软件的短时间内，记录可见角色的进程数量、CPU/RSS汇总与Claude可见TCP套接字分类。它不配置环境、不接管网络、不验证账号、不保证观测到全部进程或全部流量，也不能用来证明掉登录态、账号限制的根因。

本脚本只在macOS运行，需要客户已经安装且确认可用的Python 3.8或更新版本，只用标准库。不自动安装Python、Xcode或第三方依赖，不弹权限申请，不使用sudo。

Python不存在或未确认时
不要为了运行观测器自动安装Python。固定记录：PYTHON3_UNAVAILABLE_NOT_STARTED。
如果只有/usr/bin/python3而不确定开发工具是否已安装，先不要调用它，避免系统开发工具安装提示；记录PYTHON3_NOT_CONFIRMED_NOT_STARTED，改用下面的手动观察。
不要关闭Gatekeeper、移除quarantine、申请屏幕录制/辅助功能/全磁盘访问或更改客户网络来处理观察失败。

执行顺序
1. 让客户确认一个已经存在的专用项目输出目录。使用完整真实绝对路径，不使用~、/tmp、/var、符号链接、系统目录或用户Library/Applications目录；不能把整个用户主目录当输出目录。
2. 打开终端，用已经确认可用的Python解释器执行。示例中的路径必须换成客户批准的真实项目目录：

   /opt/homebrew/bin/python3 /已批准项目目录/collect_readonly_macos.py --output-parent /已批准项目目录/观测结果

   上例不会自动安装/查找Python；Intel Mac如使用其他解释器，明确替换路径。先确认“观测结果”目录已经存在。
3. 默认观察5分钟，每10秒采样。客户照常使用；脚本不会启动、停止、登录或重启Claude、Clash、ToDesk。可用Ctrl+C只停止观测器。
4. 客户输出目录下会新建session-<32位随机hex>子目录，包含observation.ndjson与summary.json。NDJSON以header开始，随后sample，最后footer；三类记录均标schema=hongai.passive-observation.v1、随机sessionId与utcISO。summary仅保留header/footer摘要。终端只显示随机会话目录名和固定状态，不显示原始路径。跨端统一回传observation.ndjson，summary.json可一并附上；不回传原始命令输出、账号资料或截图。

可选参数与硬限制
--duration-seconds 300：允许10–1800秒。
--interval-seconds 10：允许10–300秒。
最多180个样本，总结果文件最多5MiB；达到限制即停止，保留已写结果。不覆盖现有文件，不删除旧结果，不生成无限日志，不设置后台常驻或开机启动。
创建目录/写文件失败只返回固定错误码；请另选客户批准且可写的项目目录，不提权，不自动修改父目录权限。

采集面与数据边界
系统信息：仅系统版本、Darwin内核版本、arm64/x86_64架构。
角色汇总：Claude、Cowork、mihomo、Clash、ToDesk的可见进程数量、CPU百分比总和、RSS换算的workingSetBytesTotal（字节）。分类仅依据进程名称提示，不验证官方签名、不覆盖所有工具子进程。CPU总和可超过100%，这是多进程/多核心统计，不自动作为故障；Mac cpuPercent与Windows cpuDeltaSeconds不是同一种统计口径，不能直接换算成同一分数。
网络：只查询本次识别到的Claude进程的可见TCP套接字；记录连接状态、IPv4/IPv6、远端端口类别443/80/other、远端地址类别public/private/loopback/linklocal/reserved_or_benchmark/other及计数。文档网段、100.64/10共享地址段和198.18/15基准/fake-IP段单独归类，不当作公网泄漏。
真实PID、PPID、进程路径、命令行、真实IP、域名、用户名、机器名仅在必要的瞬时解析中使用或根本不请求，均不写入文件或终端。不读取文件正文、Cookie、Token、Keychain或浏览器资料。
TCP观察不含UDP/QUIC、数据包、URL、请求正文、TLS内容、远程服务日志或所有工具子进程；进程可能在两条命令间退出或重用PID。分类统计不是实时完整抓包，不表示所有请求都通过了某条代理。

实际命令（仅固定参数、短超时与输出上限）
/usr/bin/sw_vers
/usr/bin/uname -s -r -m
/bin/ps -axo pid,ppid,comm,%cpu,rss
/usr/sbin/lsof -nP -a -p <仅本次识别的Claude PID集合> -iTCP -FpfntT -l

lsof禁止DNS/服务名解析；不抓包，不TLS中间人，不发任何HTTP/API请求。状态区分OBSERVED（可见范围内取得数据）、EMPTY（命令成功但指定类别为空）、PARTIAL（只取得部分可见数据）和NOT_OBSERVED（无法观察）。权限不足、超时、输出超限或进程消失不能当作“没有泄漏”或“全部正常”。调度与时长上限使用monotonic时钟；UTC时间只标记时间线，不改客户系统时间。本脚本只写新建的输出会话，不改网络、Wi-Fi、代理、远控、登录资料、软件或系统权限。

手动替代（没有Python时）
打开macOS“活动监视器”，分别查看Claude/Cowork、Clash/mihomo、ToDesk的CPU和内存。每隔约10秒手工填写各角色进程数量与汇总值，持续约5分钟；不截图包含账号、路径或其他客户应用的页面。
手动表单固定标记source=MANUAL_CUSTOMER_OBSERVATION、network.status=NOT_OBSERVED、python.status=PYTHON3_UNAVAILABLE_NOT_STARTED。未测内容留NOT_OBSERVED，不补成正常，不粘贴原始ps/lsof输出。
如软件无法正常使用，由客户正常操作保留现象；不要为了补测重启、切节点、清登录态或调整TUN/DNS。

验收边界
实际CLI采集header固定source=READ_ONLY_LOCAL_COMMAND、synthetic=false。合成fixture单测通过内部API明确选择source=SYNTHETIC_FIXED_FIXTURE、synthetic=true，角色/TCP结果也沿用该来源；CLI不开放改变来源的参数。合成记录不能作为客户机器实际观测。
Windows上只能导入纯解析函数跑合成单测；主程序固定返回MACOS_REQUIRED_NOT_STARTED，不执行采集。真正macOS命令、权限可见性与持续运行验收仍须在客户批准的Mac上完成，未经验证不得标为原生采集已通过。
