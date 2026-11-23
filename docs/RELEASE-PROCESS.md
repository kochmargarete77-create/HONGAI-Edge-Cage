# HONG AI Edge Cage 可复现发布准备

`release-builder` 只从一个已提交、干净的 Git tree 生成明文源码包。它不会上传文件、不会读取授权数据库，也不会创建 GitHub Release。明文 `.tgz` 必须留在受控数据盘，随后由授权管理员工具本地加密。

客户离线试点包使用 `pilot-builder`，必须分别在 Windows x64、macOS arm64 和 macOS x64 原生构建机上生成。它打包内置 Node、预编译程序、生产依赖、平台脚本和逐文件清单；具体边界见 [PILOT-DELIVERY.md](PILOT-DELIVERY.md)。源码包和离线试点包用途不同，不得互相冒充。

## 硬门槛

- `package.json` 与 `HONGAI-DELIVERY.json` 的版本必须完全一致；两个文件都从目标 commit 读取，而不是从未绑定的工作区副本读取。
- `--project-root` 必须是仓库根目录，且 tracked、untracked 文件都不能有变化。
- 打包结束后再次核对工作树、HEAD 与 tree；构建期间任一项变化都会丢弃内存中的候选包并失败。
- Windows 输出目录只能是 D: 或 E: 的绝对路径，C: 和其他盘符会被拒绝。
- macOS/Linux 输出目录必须是绝对路径，并且所有平台都拒绝把输出写回 Git 工作树。
- 包只来自指定提交的 Git tree；`.git`、本机缓存、未提交配置和密钥不会进入包。
- tar 固定使用 `package/` 根，gzip header 时间固定为 0、OS 字段固定为 255；同一 Git tree 重复生成的 `.tgz` SHA-256 应一致。
- 可复现核对必须使用相同版本的 Node、npm、Git 与 zlib；规范化 gzip 头不能消除不同压缩器版本造成的 DEFLATE 差异。

## 操作顺序

先完成修改、测试并提交。`dist/` 被忽略，编译不会污染 Git 状态：

```powershell
npm ci --fund=false --audit=false
npm run check
npm test
npm run build
git status --short
```

工作树必须没有输出。然后在 Windows 数据盘生成明文源码包：

```powershell
npm run release:build -- `
  --project-root E:\codexdata\HONGAI-Edge-Cage `
  --output-dir E:\HONGAI-Release\0.2.0-alpha.4
```

macOS 使用已挂载的数据卷或其他绝对、非工作树路径：

```bash
npm run release:build -- \
  --project-root /Volumes/Work/HONGAI-Edge-Cage \
  --output-dir /Volumes/HONGAI-Release/0.2.0-alpha.4
```

工具输出：

- `hongai-edge-cage-<version>-<commit12>-source.tgz`
- 同名 `.build-record.json`

构建记录固定写明版本、完整 commit SHA、tree SHA、提交时间、两份发布元数据的 Git blob SHA 与 SHA-256、源码包 SHA-256、字节数以及 Node/npm/Git/zlib 版本。它不含密钥、客户资料或代理配置。

## 两次构建核对

正式候选应在两个空输出目录各执行一次，并比较结果：

```powershell
(Get-FileHash E:\HONGAI-Release\build-a\*.tgz -Algorithm SHA256).Hash
(Get-FileHash E:\HONGAI-Release\build-b\*.tgz -Algorithm SHA256).Hash
```

macOS 对应命令：

```bash
shasum -a 256 /Volumes/HONGAI-Release/build-a/*.tgz
shasum -a 256 /Volumes/HONGAI-Release/build-b/*.tgz
```

只有工具链版本、`commitSha`、`treeSha`、`version` 和源码包 SHA-256 全部一致才继续。两个 JSON 构建记录本身可以因外层记录顺序或未来新增的非规范字段而不逐字节一致，但上述门禁字段不得不同。

## 本地加密与上传边界

使用 `license-admin encrypt-artifact` 在授权环境中加密 `.tgz`，按 `docs/LICENSE-SERVICE.md` 登记签名制品清单。只有 `.enc` 可以上传 GitHub Release。

公开 CI 的三平台原生试点包使用独立的**运输加密**：runner 用 `keys/ci-artifact-transport-public.pem` 封装随机内容密钥，Actions artifact 仅包含 `.enc`、`.envelope.json` 和 `.build-record.json`。离线取回时必须用 `tools/ci-artifact-transport.mjs decrypt` 同时提供对应构建记录；该工具认证二者绑定并拒绝覆盖既有文件。运输加密不是客户授权加密，也不能替代正式制品签名、授权登记或客户机验收。

严禁上传：

- 明文 `.tgz`；
- 授权数据库、`master.key` 或签名私钥；
- 客户 YAML、代理凭据、Cookie、登录态；
- 含上述内容的 Actions artifact、终端日志或截图。

构建记录应进入内部只追加发布台账。确认 `.enc` 已上传、下载复核和授权登记完成后，再按留存策略把明文包转移到离线存储或尽力删除。SSD/NTFS/APFS 上不得承诺物理擦除。
