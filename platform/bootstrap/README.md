# HONG AI Edge Cage 客户交付启动包

该目录是离线、宿主架构匹配的最小启动器。它只负责校验启动包、读取相邻的 `delivery.json`、向授权服务取回已加密的正式安装包、验证并安装、重试待提交的安装回执，以及在人工明确放弃后提交终态。启动包不包含长期授权密钥、一次性令牌、代理密码或 Claude 运行时。

## 现场操作顺序

1. 先核对包名与客户机：Windows 11 x64 使用 `windows-x64`；苹果菜单“关于本机”显示 Apple 芯片时使用 `macos-arm64`，显示 Intel 时使用 `macos-x64`。不确定时不要猜测；错架构包会在领取前拒绝执行。
2. 交付人员从 `delivery.example.json` 复制为 `delivery.json`，填写本次客户对应的公开服务地址、制品编号和本机路径。
3. 将客户配置保存为 `customer.yaml`，将交付签名公钥保存为模板指定的文件名。
4. Windows 双击 `00-Start-HONGAI-Delivery.cmd`，确认系统 UAC 提示，然后在提升后的窗口内输入长期授权密钥和一次性令牌。
5. macOS 双击 `00-Start-HONGAI-Delivery.command`。如系统首次阻止未知来源脚本，由客户按组织安全流程在“系统设置 > 隐私与安全性”中确认；启动器不会绕过 Gatekeeper，也不会自动执行 `xattr`。
6. 如果是可重试的网络、下载或安装报错，修复原因后直接重新运行同一个 `00-Start-HONGAI-Delivery`；它会先核对已有恢复状态，不会因单纯重试再消耗一个令牌。
7. 若安装成功但回执因临时断网待提交，Windows 双击 `01-Retry-HONGAI-Receipt.cmd`，macOS 双击 `01-Retry-HONGAI-Receipt.command`。
8. 安装或网络报错默认始终保留恢复能力，绝不会自动记为 `FAILED`。只有交付人员已经完成恢复/卸载，确认解密后的主包及临时包、`installRoot` 及其失败/中断隔离目录、macOS `currentLink`/`previous` 均已按支持流程处理并从原位置移走，而且决定永久不再重试时，才可运行 `99-Explicitly-Abandon-HONGAI-Delivery`；工具会在交互前后各核验一次，并要求逐字输入包含制品编号的确认语句。断网时 `FAILED` 先进入加密 outbox，再用第 7 步重试回执。

不要把授权密钥或一次性令牌写入 `delivery.json`、脚本、快捷方式或命令行参数。客户配置会在请求令牌前完成结构与宿主平台校验。

## 异常事务锁恢复

部署、完成态恢复和人工放弃共用 `<archiveOutput>.delivery-transaction.lock`。即使 `owner.json` 中的 Node PID 已退出，工具也**不会自动删除或回收**该锁，因为已启动的 PowerShell、`/bin/sh` 或平台安装器可能仍在修改 WFP、安装 marker 或 macOS 活动链接。

遇到“owner PID 已退出”时：停止重试，不要直接删除锁；最稳妥的是先重启客户机，确保孤儿安装器全部退出。随后按平台恢复流程检查 `installRoot`、Windows `INSTALLING/INSTALLED` marker、macOS `current/previous` 与 rollback journal：中断态先执行签名包内的卸载/回滚，完成态保持不动以便下次启动器核对并补交回执。确认不再有安装进程或机器级变更后，把整个锁目录移动到 D:/E:（macOS 为指定数据卷）的恢复隔离目录留证，再重新运行 `00-Start`。不要删除 activation recovery、事务日志或隔离 payload；需要永久放弃时，必须先完成受控清理，最后才运行 `99-Explicitly-Abandon`。

## 成功交付后的客户交接

当前 Alpha 是 HONG AI 操作员受控试点，不是无人值守的公开安装器。现场人员必须在离开前：

1. 从安装结果中记录本次 `installRoot`、`customer.yaml` 绝对路径，macOS 还要记录 `currentLink`；
2. 实际运行一次对应平台的 doctor 和 Start，确认客户使用的是已绑定的配置；
3. 为客户留下一个固定、已验证的日常启动入口，不要让客户自行改写 YAML 或切换版本目录；
4. 记录脱敏支持包的输出路径，并告知客户只发送该 JSON，不发送授权密钥、令牌、代理密码或原始日志。
