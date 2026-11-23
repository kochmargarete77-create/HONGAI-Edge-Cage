# 隔离等级与指纹边界

## 当前：Process Cage

`0.2.0-alpha.2` 实现的是进程级 Cage：

- Claude 及子进程只能通过 Sandbox Runtime 的受控父代理访问白名单域名；
- 最终出口不一致或不可用时拒绝启动，运行中漂移则终止会话；
- 工作区以外的宿主浏览器、SSH、Clash、云凭据和其他项目默认不可读；
- HOME、USERPROFILE、AppData、XDG、npm、Git、GnuPG 和临时目录全部指向独立状态区；
- 宿主环境变量采用白名单继承，不传入计算机名、用户名、处理器描述、API Key 或 SSH Agent；
- 会话内即使选择“允许全部工具”，也不能解除操作系统外层的网络和文件围栏。

这一等级可以隔离大部分软件身份与登录状态，但不能承诺隐藏由宿主内核直接提供的全部硬件信息。例如 CPU 架构、系统版本、部分设备能力和计时特征仍可能被进程观察到。

## 规划：Sealed VM

真正的硬件指纹隔离需要每位客户独立的密封虚拟机：

- Windows 使用 Hyper-V/Windows Hypervisor Platform；
- macOS 使用 Apple Virtualization.framework；
- 固定虚拟 CPU、磁盘、网卡和机器身份；
- 仅映射客户批准的工作区，不直通宿主浏览器配置、密钥链或设备；
- 虚拟机唯一出站连接到宿主 Edge Cage 网关，网关仍执行最终出口锁定；
- 基础镜像签名、只读，客户状态放在独立加密差分盘；
- 每次升级执行快照、负向测试和可回滚切换。

Sealed VM 在通过 Windows/macOS 支持矩阵和恢复测试前不会在界面标记为可用。Process Cage 与 Sealed VM 的报告不得混用。
