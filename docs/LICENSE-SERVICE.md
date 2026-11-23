# HONG AI Edge Cage 授权服务运维

授权服务负责把“长期授权密钥 + 一次性临时令牌 + 指定 GitHub Release 制品”绑定为一次可审计的领取。它不依靠隐藏算法：安全性来自服务端私钥、主密钥、单次令牌、签名信封、制品哈希和 TLS。

## 生产边界

- 公开仓库只保存代码和公开签名公钥，不保存数据库、私钥、主密钥、客户资料或代理配置。
- `HONGAI_LICENSE_DATA_ROOT` 必须位于受备份和磁盘加密保护的数据盘；服务只能单实例写入同一数据库。
- 服务默认只监听 `127.0.0.1:8787`，生产环境由 Caddy、Nginx 或云负载均衡终止 TLS。
- 若反向代理会覆盖而不是追加客户端地址头，可设置 `HONGAI_LICENSE_TRUSTED_PROXY=1`；否则不要启用。
- GitHub Release 中只能上传 `.enc` 加密制品。明文客户包不得进入仓库、Release 或 Actions 日志。

## 初始化

以下示例在本地开发机使用 D 盘。生产服务器应换成服务器上的加密数据卷：

```powershell
npm ci
npm run build
npm run license:admin -- init --data-root D:\HONGAI-License-Service
```

该命令生成签名私钥、公钥、数据库主密钥和审计数据库。至少分别离线备份签名私钥和主密钥，不要把二者放在同一份公开或在线备份中。

## 生成加密 Release 制品

先从已经通过 CI 的提交生成固定 `package/` 根目录源码包。`git archive` 只收录已提交文件，不会带入本机配置、密钥、缓存或 `.edge-cage` 状态：

```powershell
git archive --format=tar.gz --prefix=package/ `
  --output E:\release\edge-cage-0.2.0-windows-x64.tgz `
  COMMIT_SHA
```

再由管理员工具一次完成加密和内容密钥入库：

```powershell
npm run license:admin -- encrypt-artifact `
  --data-root D:\HONGAI-License-Service `
  --artifact-id edge-cage-0.2.0-windows-x64 `
  --input E:\release\edge-cage-0.2.0-windows-x64.tgz `
  --output E:\release\edge-cage-0.2.0-windows-x64.tgz.enc `
  --download-url https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/releases/download/v0.2.0/edge-cage-0.2.0-windows-x64.tgz.enc
```

只上传 `.enc` 文件。确认上传地址与登记地址完全一致后，安全删除临时明文包或转移到离线归档。

## 签发与领取

首次交付签发长期授权和 30 分钟单次令牌：

```powershell
npm run license:admin -- issue `
  --data-root D:\HONGAI-License-Service `
  --customer-id customer-001 `
  --artifact-id edge-cage-0.2.0-windows-x64 `
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
  --artifact-id edge-cage-0.2.0-windows-x64 `
  --signing-public-key D:\HONGAI\signing-public.pem `
  --output D:\HONGAI\Delivery\edge-cage-0.2.0-windows-x64.tgz
```

客户端会核对授权服务签名、安装 ID、五分钟信封时效、密文 SHA-256 和明文 SHA-256。输出文件已存在时拒绝覆盖。成功后回传 `DELIVERED`；实际平台安装器完成后再回传 `INSTALLED`。

需要一条链完成领取、解包和部署时，在 Windows 管理员终端或具备相应 macOS 权限的终端运行：

```powershell
npm run delivery:deploy -- `
  --service-url https://license.example.com/ `
  --artifact-id edge-cage-0.2.0-windows-x64 `
  --signing-public-key D:\HONGAI\signing-public.pem `
  --archive-output D:\HONGAI\Delivery\edge-cage-0.2.0-windows-x64.tgz `
  --install-root D:\HONGAI\Edge-Cage-0.2.0 `
  --config D:\HONGAI\customer.yaml
```

自动部署只接受 `package/` 根目录、含 `HONGAI-DELIVERY.json` 的源码包；路径穿越、绝对路径、反斜杠路径、符号链接、硬链接和超过条目上限的包都会被拒绝。安装目录已存在时不会覆盖。Windows/macOS 固定安装脚本成功后才记录 `INSTALLED`，失败则记录 `FAILED`。

## 审计与恢复

```powershell
npm run license:admin -- verify-audit --data-root D:\HONGAI-License-Service
```

任何历史事件被修改都会破坏后续哈希链并使服务拒绝继续签发。数据库应按业务量定期做只读快照；恢复后必须先运行审计验证再启动服务。

服务端不记录许可证、临时令牌、代理密码、Cookie、Claude 登录态或发布内容密钥的明文。客户端地址只以带服务端 pepper 的哈希留存。
