# HONG AI Edge Cage 受控客户试点交付手册

## 交付级别

`0.2.0-alpha.4` 的目标是 **HONG AI 操作员受控现场/远程试点**：客户机无需安装 Node、npm、Homebrew 或编译工具，主包可在网络配置完成前离线落盘。当前制品尚未完成 Windows Authenticode、Apple Developer ID 签名与 Apple 公证，因此不得作为无人工协助的正式群发安装器。

每个平台必须使用本机架构构建，严禁混用：

- Windows 11 x64：`windows-x64`；
- Apple Silicon Mac：`macos-arm64`；
- Intel Mac：`macos-x64`。

## 第三方软件与账号边界

交付包只携带 Anthropic 官方发布、未经修改的 Claude Code 二进制；HONG AI 不修改、替换或屏蔽其任何官方认证方式，也不代客户保管、转售或中转 Claude 凭据与用量。客户必须在现场自行完成官方登录，并使用由客户自己持有和付费的 Claude 订阅、API Key 或受支持的第三方推理提供商凭据。HONG AI Edge Cage 是独立的本地隔离与交付控制产品，不代表 Anthropic 开发、认可或合作。

公开 GitHub 仓库只发布 HONG AI 自有源代码。含第三方运行时的客户制品不得以明文附件公开；只允许通过受控授权下载或经授权操作员离线交付，并必须保留包内第三方许可证与声明。

## 构建与制品

提交、测试并确认工作树干净后，在对应平台执行：

```text
npm ci --fund=false --audit=false
npm test
npm run pilot:build -- --project-root <仓库绝对路径> --output-dir <仓库外数据盘目录>
```

生成物包含架构原生 Node 24、预编译控制器、生产依赖、官方 Claude Code、Sandbox Runtime、平台脚本和逐文件 SHA-256 清单。macOS 包还包含架构匹配的 `runtime/bin/rg`。客户安装阶段不得运行 `npm`、`npx`、Homebrew 或在线下载运行时。

GitHub Actions 在 `windows-2025`、`macos-15` 和 `macos-15-intel` 上分别构建并验证三种原生制品。由于本仓库公开，工作流绝不上传明文客户主包。在 `main` 推送或手动触发时，原生 `.tgz` 在 runner 内使用每次随机 AES-256-GCM 内容密钥加密，该内容密钥再由仓库内 4096 位 RSA 公钥以 OAEP-SHA256 封装；Actions 只保留 7 天的 `.enc`、认证信封、非敏感构建记录和无密钥公开启动包。RSA 私钥只在 HONG AI 离线保管环境中存在，不进入仓库、Actions secret、日志或客户机。Actions 构建通过不等于真实客户机验收通过。

每次符合条件的工作流会生成以下 6 个 Actions artifact（均保留 7 天）：

- `hongai-edge-cage-encrypted-native-windows-x64`
- `hongai-edge-cage-encrypted-native-macos-arm64`
- `hongai-edge-cage-encrypted-native-macos-x64`
- `hongai-edge-cage-bootstrap-windows-x64`
- `hongai-edge-cage-bootstrap-macos-arm64`
- `hongai-edge-cage-bootstrap-macos-x64`

从指定 commit 的工作流下载三件套后，在受控数据盘执行解密；输出路径必须尚不存在：

```text
node tools/ci-artifact-transport.mjs decrypt \
  --input <绝对路径/原生包.tgz.enc> \
  --output <绝对路径/原生包.tgz> \
  --envelope <绝对路径/原生包.tgz.enc.envelope.json> \
  --private-key <离线运输私钥绝对路径> \
  --build-record <绝对路径/原生包.tgz.build-record.json>
```

工具会同时验证私钥标识、信封认证、密文哈希、明文哈希、文件大小、原始文件名和构建记录绑定，并拒绝覆盖现有输出。CI 运输加密只用于把原生构建结果安全带出公开 runner；解密后的包必须立即进入受控离线交付或授权服务的正式制品加密流程，不得把运输私钥或明文包发送给客户。

当前 alpha 启动包的文件清单提供完整性检测，但没有独立代码签名信任根。受控交付人员必须在交接前通过独立渠道核对 build record 中的 `manifestSha256`，并保持启动包只读；未完成 Authenticode、Apple 签名/公证和清单独立签名之前，不得宣称其为公开自助安装器。

## 客户机安装顺序

1. 核对客户授权、平台、CPU 架构、目标数据盘和客户 YAML。
2. 先确认客户 YAML 中的 `network.localProxyUrl` 是正在监听的 Clash 本地 HTTP 代理；领取客户端会显式通过该回环代理访问授权服务与 GitHub Release，不依赖 Windows“系统代理”是否被 Node 识别，也不允许把授权请求转交给远端或带凭据的代理 URL。
3. 再运行不消耗一次性令牌的本地预检；目标目录必须不存在并至少有 3 GiB 空间。
4. 领取客户端在本地生成 X25519 安装身份，并把恢复状态用长期授权密钥派生的 AES-256-GCM 密钥加密保存。
5. 输入长期授权密钥和一次性令牌；两者只允许在交互式隐藏输入中出现。
6. 下载加密 GitHub Release，验证签名、密文哈希、明文哈希、归档路径和逐文件清单。
7. 把已验证包原子放入最终版本目录，再执行平台安装器。
8. Windows 仅在新机状态下创建专用沙箱账号/WFP；失败自动撤销本次创建的状态。已有共享 SRT 默认只验证、不升级、不删除。
9. macOS 运行 Seatbelt 自检；需要版本切换时显式调用 `activate.sh <版本目录> <current链接>`。
10. doctor 全部通过后记录 `INSTALLED` 回执；回执网络失败进入加密 outbox，不把成功安装误标为失败。
11. 任意可重试的下载、网络、预检、安装或 doctor 故障都保留 activation recovery，绝不自动记录 `FAILED`。仅在现场人员已安全恢复/卸载，解密后的主包及临时包、安装目标及其失败/中断隔离目录、macOS `current/previous` 链接均已按支持流程处理并从原位置移走，并逐字确认永久放弃后，才允许生成 `FAILED` 加密回执；断网仍可稍后幂等补交。
12. 由客户本人在未修改的官方界面完成登录。登录 URL、验证码、Token、Cookie 和 API Key 不进入交付记录、支持包或 HONG AI 服务端。

### 崩溃后的事务锁（fail-closed）

`<archiveOutput>.delivery-transaction.lock` 同时串行化 deploy、已完成安装回执恢复和 explicit abandon。锁的 Node owner 消失后不得自动判定安全：其 PowerShell、shell 或安装器子进程可能仍存活，因此客户端会保持锁并停止。现场人员应先停止重复点击；无法证明所有子进程退出时先重启。重启后检查平台 marker、WFP/SRT 状态、macOS `current/previous` 与 rollback journal，按签名包内的卸载/回滚流程处理未完成事务；若安装已完整则保持现场，等待启动器核验。最后把锁目录整体移动到 D:/E: 或 macOS 数据卷的恢复隔离目录留证，再重跑启动器，由正常恢复分支继续。禁止为了“解锁”而删除 activation recovery、事务日志、明文包或安装目录。

## Windows 现场命令

以下命令在管理员 PowerShell 中执行，路径必须位于 D: 或 E:：

```powershell
& 'D:\HONGAI\versions\<版本>\platform\windows\Install-HONGAI-Edge-Cage.ps1' `
  -ConfigPath 'D:\HONGAI\customer.yaml'

& 'D:\HONGAI\versions\<版本>\platform\windows\Test-HONGAI-Edge-Cage.ps1' `
  -ConfigPath 'D:\HONGAI\customer.yaml'

& 'D:\HONGAI\versions\<版本>\platform\windows\Start-HONGAI-Edge-Cage.ps1' `
  -ConfigPath 'D:\HONGAI\customer.yaml'
```

卸载时使用同版本目录中的 `Uninstall-HONGAI-Edge-Cage.ps1`。它只在安装状态证明本产品拥有该机器级 SRT/WFP 时移除；客户工作区与隔离状态默认保留。

## macOS 现场命令

```bash
sh '/Volumes/HONGAI/versions/<版本>/platform/macos/install.sh' '/Volumes/HONGAI/customer.yaml'
sh '/Volumes/HONGAI/versions/<版本>/platform/macos/activate.sh' \
  '/Volumes/HONGAI/versions/<版本>' '/Volumes/HONGAI/current'
sh '/Volumes/HONGAI/current/platform/macos/doctor.sh' '/Volumes/HONGAI/customer.yaml'
sh '/Volumes/HONGAI/current/platform/macos/start.sh' '/Volumes/HONGAI/customer.yaml'
```

回滚使用 `rollback.sh /Volumes/HONGAI/current`。卸载器先核验安装标记，默认保留客户状态；只有显式 `--remove-program` 才移除已经核验的程序版本目录。

## 脱敏支持包

遇到问题时使用包内 Node 生成 JSON 支持包。下列命令必须使用已安装版本自带的 Node，不得改用系统 Node。

Windows：

```powershell
& 'D:\HONGAI\versions\<版本>\runtime\node.exe' `
  'D:\HONGAI\versions\<版本>\dist\src\cli.js' support-bundle `
  --config 'D:\HONGAI\customer.yaml' `
  --output 'D:\HONGAI\support\hongai-support.json'
```

macOS：

```bash
'/Volumes/HONGAI/current/runtime/bin/node' \
  '/Volumes/HONGAI/current/dist/src/cli.js' support-bundle \
  --config '/Volumes/HONGAI/customer.yaml' \
  --output '/Volumes/HONGAI/support/hongai-support.json'
```

通用形式：

```text
<bundled-node> dist/src/cli.js support-bundle --config <customer.yaml> --output <support.json>
```

支持包只包含平台/架构、制品完整性、预检布尔结果、出口 IP 指纹、沙箱 smoke 结果和审计链健康度；不包含代理凭据、授权密钥、OTP、完整 IP、完整客户路径或原始日志。

## 首批试点硬门槛

- 三个平台 CI 构建通过，包内架构与宿主严格一致；
- 无 Node/npm/Homebrew 的干净客户机仍可安装；
- 最终出口不一致、本地代理失效、时区不一致时拒绝启动；
- Claude/Anthropic 流量无 DIRECT 备用路径，出口失效后会话终止；
- Windows 新装失败能撤销本次 WFP/SRT，既有共享安装不会被误删；
- macOS activate/rollback 只切换通过安装标记核验的版本；
- doctor 与支持包可运行；
- 客户使用自己控制的官方账号完成未修改的官方登录流程。

真实 Windows 管理员/WFP、Apple Silicon、Intel Mac 和签名/公证仍须分别留存现场验收记录。没有这些记录时，只能标记为“受控试点”，不能标记为“正式自助交付”。
