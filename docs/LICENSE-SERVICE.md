# HONG AI Edge Cage 授权服务运维

授权服务负责把“长期授权密钥 + 一次性临时令牌 + 指定 GitHub Release 制品”绑定为一次可审计的领取。它不依靠隐藏算法：安全性来自服务端私钥、主密钥、单次令牌、签名制品清单、安装绑定信封、制品哈希和 TLS。

## 生产边界

- 公开仓库只保存代码；正式启动器应内置并签名固定的公开签名公钥或指纹。仓库绝不保存数据库、私钥、主密钥、客户资料或代理配置。
- `HONGAI_LICENSE_DATA_ROOT` 必须位于受备份和磁盘加密保护的数据盘。在线服务和管理员命令共用跨进程锁；正式环境仍只运行一个在线服务实例。
- 服务默认只监听 `127.0.0.1:8787`，生产环境由 Caddy、Nginx 或云负载均衡终止 TLS。
- 非回环监听默认被拒绝；只有在 TLS 反代和防火墙已经就绪时才可显式设置 `HONGAI_LICENSE_ALLOW_PUBLIC_BIND=1`。
- 若反向代理会覆盖而不是追加客户端地址头，可设置 `HONGAI_LICENSE_TRUSTED_PROXY=1`；否则不要启用。
- GitHub Release 中只能上传 `.enc` 加密制品。明文客户包不得进入仓库、Release 或 Actions 日志。
- 制品登记默认只接受 `kochmargarete77-create/HONGAI-Edge-Cage` 的 Release；自托管 fork 必须显式设置 `HONGAI_RELEASE_REPOSITORY=owner/repo`。

## 初始化

以下示例在本地开发机使用 D 盘。生产服务器应换成服务器上的加密数据卷：

```powershell
npm ci
npm run build
npm run license:admin -- init --data-root D:\HONGAI-License-Service
```

该命令生成签名私钥、公钥、数据库主密钥和审计数据库。至少分别离线备份签名私钥和主密钥，不要把二者放在同一份公开或在线备份中。

## 生成加密 Release 制品

客户部署只接受 `pilot-builder` 在目标原生平台生成的 `portable` 离线包。`release:build` 生成的 `source` 包仅供内部复核，部署客户端会在兑换令牌前拒绝它，严禁把 source 包登记为客户安装制品。

Windows x64 示例（macOS arm64/x64 必须在对应 Mac 或对应 GitHub Runner 上分别执行）：

```powershell
npm ci --fund=false --audit=false
npm run build
npm run pilot:build -- `
  --project-root E:\codexdata\HONGAI-Edge-Cage `
  --output-dir E:\HONGAI-Release\0.2.0-alpha.4\windows-x64
```

构建器输出的制品 ID 形如 `hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12`。加密、签名登记与 GitHub Release 文件名必须使用同一 ID：

```powershell
npm run license:admin -- encrypt-artifact `
  --data-root D:\HONGAI-License-Service `
  --artifact-id hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12 `
  --input E:\HONGAI-Release\0.2.0-alpha.4\windows-x64\hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12.tgz `
  --output E:\HONGAI-Release\0.2.0-alpha.4\windows-x64\hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12.tgz.enc `
  --download-url https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/releases/download/v0.2.0-alpha.4/hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12.tgz.enc
```

只上传 `.enc`。登记前核对 build record、平台、架构、明文哈希、密文哈希和 Release URL；明文包转移到离线存储或按留存策略删除。

## 签发与领取

首次交付签发长期授权和 30 分钟单次令牌：

```powershell
npm run license:admin -- issue `
  --data-root D:\HONGAI-License-Service `
  --customer-id customer-001 `
  --artifact-id hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12 `
  --ttl-minutes 30
```

明文密钥只显示一次。后续领取只补发临时令牌：

```powershell
npm run license:admin -- issue-token `
  --data-root D:\HONGAI-License-Service `
  --license-id INTERNAL-LICENSE-ID `
  --ttl-minutes 30
```

客户端通过交互式终端输入两段密钥，密钥不会出现在命令行历史：

```powershell
npm run delivery:retrieve -- `
  --service-url https://license.example.com/ `
  --artifact-id hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12 `
  --signing-public-key D:\HONGAI\signing-public.pem `
  --output D:\HONGAI\Delivery\hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12.tgz
```

客户端在兑换前创建加密恢复状态；令牌原子绑定 artifact、installId 与 X25519 公钥。同一绑定可幂等重试，下载中断后使用 24 小时恢复令牌续发五分钟密钥信封。密文先流式落盘并计算 SHA-256，再流式认证解密，避免把约 500 MB 主包同时放入内存。成功领取回传 `DELIVERED`；平台安装器及 doctor 完成后回传 `INSTALLED`。

授权服务只把白名单内、可明确归因于请求本身的错误返回为 4xx；数据库锁、审计链、磁盘、签名和其他内部故障统一返回 `500 INTERNAL_ERROR`。领取客户端仅在明确的非重试 4xx 后删除一份刚创建且尚未绑定的恢复态；HTTP 408/409/425/429、任何 5xx、无效响应或网络中断都会保留原 `installId` 和 X25519 身份，下一次重试不得重新绑定已经消费的单次令牌。

如果授权服务在领取或安装完成后暂时不可达，客户端不会把回执令牌明文落盘，而是使用长期授权密钥经 scrypt 派生的 AES-256-GCM 密钥写入加密 outbox，并在结果中的 `receiptPendingPath` 明确返回绝对路径。网络恢复后，用同一长期授权密钥重试；服务端对同状态回执是幂等的：

```powershell
npm run delivery:receipt -- `
  --pending D:\HONGAI\Delivery\edge-cage.tgz.receipt-HASH.pending.json
```

macOS 数据卷示例：

```bash
npm run delivery:receipt -- \
  --pending /Volumes/HONGAI/Delivery/edge-cage.tgz.receipt-HASH.pending.json
```

命令会在交互式终端隐藏读取长期授权密钥，成功提交后才删除 outbox 文件。不要改名、编辑或发送该文件；密钥不匹配或文件被篡改时认证解密会失败并保留原文件。

领取、平台安装恢复和显式放弃由 `<archiveOutput>.delivery-transaction.lock` 串行化。死掉的 Node owner 不会触发自动回收，因为平台安装器子进程可能继续运行；此时按 `PILOT-DELIVERY.md` 的 fail-closed 流程重启/核验/恢复，并把锁目录移入数据盘恢复隔离区留证后再重试。

`FAILED` 是不可逆终态，不会由下载、断网、安装或 doctor 异常自动触发。只有人工完成恢复/卸载，确认解密后的主包及临时包、安装目录及其失败/中断隔离目录、macOS 活动/回退链接均已按支持流程处理并从原位置移走，而且决定永久不再重试时，才运行启动包中的 `99-Explicitly-Abandon-HONGAI-Delivery`。命令会在交互前后各核验一次，要求逐字输入 `确认放弃 <artifactId>`，再隐藏输入长期授权密钥；它先把 `FAILED` 写入 AES-256-GCM 加密 outbox，再尝试联网提交。若断网，使用同一个 `01-Retry-HONGAI-Receipt` 补交。该路径不会替操作员删除或覆盖任何恢复现场；原始现场须先审阅，再移动到恢复隔离区留证或按批准的安全清理流程处理。

需要一条链完成领取、解包和部署时，在 Windows 管理员终端或具备相应 macOS 权限的终端运行：

```powershell
npm run delivery:deploy -- `
  --service-url https://license.example.com/ `
  --artifact-id hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12 `
  --signing-public-key D:\HONGAI\signing-public.pem `
  --archive-output D:\HONGAI\Delivery\hongai-edge-cage-0.2.0-alpha.4-windows-x64-COMMIT12.tgz `
  --install-root D:\HONGAI\Edge-Cage\versions\0.2.0-alpha.4 `
  --config D:\HONGAI\customer.yaml
```

macOS 上使用独立数据卷或用户有写权限的非系统工作目录，并保持长期授权密钥和单次令牌为终端隐藏输入：

```bash
npm run delivery:deploy -- \
  --service-url https://license.example.com/ \
  --artifact-id hongai-edge-cage-0.2.0-alpha.4-macos-arm64-COMMIT12 \
  --signing-public-key /Volumes/HONGAI/signing-public.pem \
  --archive-output /Volumes/HONGAI/Delivery/hongai-edge-cage-0.2.0-alpha.4-macos-arm64-COMMIT12.tgz \
  --install-root /Volumes/HONGAI/Edge-Cage/versions/0.2.0-alpha.4 \
  --current-link /Volumes/HONGAI/Edge-Cage/current \
  --config /Volumes/HONGAI/customer.yaml
```

自动部署只接受 ID、平台和架构匹配的 portable 包。压缩包路径、入口类型、展开体积、清单 provenance 以及每个文件的长度/SHA-256 都必须通过。验证完成后包先在同卷原子放入最终版本目录，再运行平台安装器；失败时 Windows 撤销本次新建的 SRT/WFP，部署器把失败现场移到恢复目录并保留事务记录。可重试的本地安装失败不会自动发送 `FAILED` 或销毁 activation；doctor 通过后才发送 `INSTALLED`。

## 查询与撤销

查询全局或单个许可证的脱敏状态：

```powershell
npm run license:admin -- status --data-root D:\HONGAI-License-Service
npm run license:admin -- status --data-root D:\HONGAI-License-Service --license-id INTERNAL-LICENSE-ID
```

撤销许可证会立即禁用长期密钥，并作废该许可证尚未使用的临时令牌：

```powershell
npm run license:admin -- revoke-license `
  --data-root D:\HONGAI-License-Service `
  --license-id INTERNAL-LICENSE-ID
```

`0.2.0-alpha.2` 之后的新密钥携带不可预测内部 ID，只需一次 scrypt 校验。`0.2.0-alpha.4` 起默认拒绝旧格式密钥与未签名制品。只有在明确排期、可审计的旧数据迁移窗口内，才临时设置 `HONGAI_LICENSE_ALLOW_LEGACY_KEYS=1` 和 `HONGAI_LICENSE_ALLOW_LEGACY_ARTIFACTS=1`；迁移后立即移除。

## 审计与恢复

```powershell
npm run license:admin -- verify-audit --data-root D:\HONGAI-License-Service
npm run license:admin -- checkpoint `
  --data-root D:\HONGAI-License-Service `
  --output E:\HONGAI-Audit-Checkpoints\checkpoint-2026-11-22.json
npm run license:admin -- verify-checkpoint `
  --data-root D:\HONGAI-License-Service `
  --checkpoint E:\HONGAI-Audit-Checkpoints\checkpoint-2026-11-22.json
```

任何历史事件被修改都会破坏后续哈希链并使服务拒绝继续签发；服务启动前也会验证审计链、32 字节主密钥、Ed25519 密钥对及已登记制品清单。`checkpoint` 对数据库快照摘要和审计链尾部签名，必须复制到与授权服务器权限隔离的只追加/WORM 存储；留在同机不能形成独立证据。数据库应按业务量定期做一致性快照；恢复后必须先运行审计和检查点验证再启动服务。

服务端不记录许可证、临时令牌、代理密码、Cookie、Claude 登录态或发布内容密钥的明文。客户端地址只以带服务端 pepper 的哈希留存。

## 尚未解除的正式发布门槛

- 试点包已固定 Node、Claude Code、Sandbox Runtime 与离线生产依赖；仍需在三种真实目标机完成提权安装、故障注入、回滚和卸载验收。
- activation 恢复态和回执 outbox 已使用长期授权密钥经 scrypt + AES-GCM 保护；正式安装器仍应接入 Windows DPAPI/macOS Keychain，并在启动时自动冲洗 outbox。
- 大包已流式下载/解密，但尚未实现 HTTP Range/ETag 断点续传；网络中断会保留 activation、重新下载密文。
- Windows 私钥、数据库和解密包仍需显式 NTFS ACL；`mode: 0o600` 不能替代 ACL。
- 正式启动器必须 Authenticode/Apple 签名并固定授权服务 origin 与签名公钥。
- 需要在干净 Windows 11、Apple Silicon macOS，以及承诺支持时的 Intel Mac 上做安装、断网、磁盘满、崩溃、回滚和卸载演练。
