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

先从已经通过 CI 的提交生成固定 `package/` 根目录源码包。`git archive` 只收录已提交文件，不会带入本机配置、密钥、缓存或 `.edge-cage` 状态：

```powershell
git archive --format=tar.gz --prefix=package/ `
  --output E:\release\edge-cage-0.2.0-alpha.2-source.tgz `
  COMMIT_SHA
```

再由管理员工具一次完成加密和内容密钥入库：

```powershell
npm run license:admin -- encrypt-artifact `
  --data-root D:\HONGAI-License-Service `
  --artifact-id edge-cage-0.2.0-alpha.2-source `
  --input E:\release\edge-cage-0.2.0-alpha.2-source.tgz `
  --output E:\release\edge-cage-0.2.0-alpha.2-source.tgz.enc `
  --download-url https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/releases/download/v0.2.0-alpha.2/edge-cage-0.2.0-alpha.2-source.tgz.enc
```

只上传 `.enc` 文件。确认上传地址与登记地址完全一致后，安全删除临时明文包或转移到离线归档。

## 签发与领取

首次交付签发长期授权和 30 分钟单次令牌：

```powershell
npm run license:admin -- issue `
  --data-root D:\HONGAI-License-Service `
  --customer-id customer-001 `
  --artifact-id edge-cage-0.2.0-alpha.2-source `
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
  --artifact-id edge-cage-0.2.0-alpha.2-source `
  --signing-public-key D:\HONGAI\signing-public.pem `
  --output D:\HONGAI\Delivery\edge-cage-0.2.0-alpha.2-source.tgz
```

客户端会先验证输出目录、硬链接能力和“不覆盖”条件，再消耗一次性令牌；随后核对签名制品清单、安装 ID、五分钟信封时效、密文 SHA-256 和明文 SHA-256。制品 URL 与两段哈希都被签名，内容密钥信封同时绑定制品清单哈希。成功后回传 `DELIVERED`；实际平台安装器完成后再回传 `INSTALLED`。

需要一条链完成领取、解包和部署时，在 Windows 管理员终端或具备相应 macOS 权限的终端运行：

```powershell
npm run delivery:deploy -- `
  --service-url https://license.example.com/ `
  --artifact-id edge-cage-0.2.0-alpha.2-source `
  --signing-public-key D:\HONGAI\signing-public.pem `
  --archive-output D:\HONGAI\Delivery\edge-cage-0.2.0-alpha.2-source.tgz `
  --install-root D:\HONGAI\Edge-Cage-0.2.0-alpha.2 `
  --config D:\HONGAI\customer.yaml
```

自动部署只接受 `package/` 根目录、含 `HONGAI-DELIVERY.json` 的源码包；路径穿越、绝对路径、反斜杠、符号/硬链接、设备文件、大小写或 Unicode 归一化碰撞、Windows 保留名、超条目数和超展开体积都会被拒绝。安装先在同卷 staging 中完成，通过后才原子移动到正式目录；失败默认删除 staging 和解密包。回执支持同状态幂等重试，终态不得回退。

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

`0.2.0-alpha.2` 的新密钥携带不可预测内部 ID，只需一次 scrypt 校验。为兼容 alpha.1 已签发密钥，迁移期默认保留旧格式；完成轮换后设置 `HONGAI_LICENSE_ALLOW_LEGACY_KEYS=0` 和 `HONGAI_LICENSE_ALLOW_LEGACY_ARTIFACTS=0`。

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

- 客户机目前仍会执行在线 `npm ci`；正式安装器必须改为固定运行时和离线依赖。
- 回执有三次即时重试，但还没有受系统密钥保护的持久 outbox。
- Windows 私钥、数据库和解密包仍需显式 NTFS ACL；`mode: 0o600` 不能替代 ACL。
- 正式启动器必须 Authenticode/Apple 签名并固定授权服务 origin 与签名公钥。
- 需要在干净 Windows 11、Apple Silicon macOS，以及承诺支持时的 Intel Mac 上做安装、断网、磁盘满、崩溃、回滚和卸载演练。
