# HONG AI Edge Cage 部署说明

## 一份客户配置完成整套交付

每台客户电脑只维护一份 YAML。日常需要填写或确认的关键项是：

1. `chain.clashProfileName`：客户 Clash 中现有的机场代理组。
2. `chain.preferredFrontNode`：指定前置节点。
3. `chain.landing`：最终 SOCKS5/HTTP 出口的 IPv4、端口和凭据环境变量名。
4. `network.expectedExit`：验收时必须观察到的最终 IPv4、国家和时区。
5. `workspace.path`：唯一允许 Claude 读写的客户项目目录。

其余安全项不建议客户改动。

最简现场参数文件使用 `config/intake.example.yaml`。填写后生成完整配置：

```powershell
node dist/src/cli.js init --config config/intake.example.yaml --output config/customer.local.yaml
```

Windows 与 macOS 路径、官方必需域名、严格白名单、监控频率、90 分交付阈值和文件隔离规则均由编译器自动补齐。

## 部署顺序

1. 复制对应平台模板为客户专属配置，保留原模板不动。
2. 在安装进程中临时设置落地代理的用户名和密码环境变量。
3. 运行 `clash-script` 生成客户专属 Clash 全局脚本，导入后重载配置。
4. 运行 `preflight`，连续三次出口必须完全一致。
5. Windows 运行安装脚本，建立专用沙箱账号与 WFP 出站围栏；macOS 直接使用 Seatbelt 沙箱。
6. 首次启动完成官方登录。若浏览器回调无法进入沙箱，使用官方提供的手动授权码回填流程。
7. 运行 HONG AI 验收；正式交付阈值默认 90 分，所有硬门槛必须通过。

## 生成 Clash 脚本

Windows PowerShell 示例：

```powershell
$env:EDGE_CAGE_LANDING_USERNAME = '<客户落地用户名>'
$env:EDGE_CAGE_LANDING_PASSWORD = '<客户落地密码>'
node dist/src/cli.js clash-script --config D:\HONGAI-Edge-Cage\customer.yaml --output D:\HONGAI-Edge-Cage\clash-global-script.js
Remove-Item Env:EDGE_CAGE_LANDING_USERNAME, Env:EDGE_CAGE_LANDING_PASSWORD
```

生成文件包含客户代理凭据，只能导入授权客户的设备。脚本具备幂等性：重复导入不会重复创建节点、代理组或规则。

## 故障封闭逻辑

- 启动前：本地代理端口、连续出口、平台和时区任一不合格，拒绝启动。
- 运行中：每 30 秒从同一本地代理探测最终出口；连续两次失败或不一致，终止 Claude 会话。
- Clash：所有允许访问的 Claude 域名和出口探针域名只指向单一链式落地组；该组没有 `DIRECT`、旧出口或前置单跳备用项。
- 沙箱：进程只能通过运行时的受控本地代理通道联网；私网、链路本地、回环和保留地址作为目标地址时被拒绝。

## 账号与历史状态

HONG AI Edge Cage 不删除客户原有 Claude、浏览器或 Clash 数据。它通过独立 `HOME`、`USERPROFILE` 和 `CLAUDE_CONFIG_DIR` 创建新的隔离状态，因此宿主机旧登录态、旧缓存和软件指纹不会被新环境继承。需要真正的临时环境时使用 `ephemeral` 模式；当前 alpha 版优先交付 `isolated-persistent`，便于客户保持自己的官方登录。

## 回滚

- 先停止 Edge Cage 会话。
- 撤销 Clash 全局脚本或切回导入前备份。
- Windows 运行 `Uninstall-HONGAI-Edge-Cage.ps1`，只移除专用账号和 WFP 规则，默认保留客户状态。
- macOS 没有常驻系统围栏；停止进程即撤销 Seatbelt 策略，状态目录默认保留。
