# HONG AI Environment · macOS 原生安装前端

本目录将已通过原生测试的 Go runtime 包装成普通 `.app` 与 **unsigned `.pkg`**。这是环境准备与诊断工作台的安装入口；官方 Claude 保留原位置、签名、账号资料与正常升级方式。界面由本地工作台在默认浏览器中呈现，启动官方 Claude 后仍是官方桌面界面。

不提供硬件身份模拟、所有进程强制出口隔离、登录验证或防封保证；安装成功不等于客户账号和业务验收完成。

## 客户操作

1. 从受信交付渠道核对包与独立提供的 SHA-256。双击 `.pkg`，按正常 macOS 安装流程批准安装到 `/Applications/HONG AI Environment.app`。系统域安装可能要求管理员授权。
2. 安装器结束后，由客户自己的正常用户打开「应用程序 → HONG AI Environment」。安装器不自动运行用户进程，不以 root 初始化用户资料。
3. 首次打开进入本地配置/诊断工作台；后续双击同一个 `.app`，已保存且核验通过的配置走日常启动流程，异常时返回工作台。客户已安装的官方 Claude 由原生 `open -a` 激活，不私自复制或修改官方包。
4. 没有管理员权限时，可以使用附带的 `-app.zip`，正常解压后拖入本人 `~/Applications`。**二选一保留一个入口**，避免用户目录与系统目录存在不同版本。不要在 ZIP 内直接启动，不要把 runtime 单独改名移动。

此试点包没有 Developer ID 签名或 Apple notarization；`.app` 仅有 ad-hoc 完整性签名。macOS 可能提示未识别开发者或拒绝安装/打开。客户应通过正常系统安全审批流程核验来源；文档和脚本均不执行关闭 Gatekeeper、移除 quarantine 或绕过企业管理策略的操作。商业正式分发应补齐 Developer ID Application、Developer ID Installer 签名与 notarization 后重新验收。

## 客户电脑需要与不需要的权限

| 部分 | 行为与边界 |
|---|---|
| 安装权限 | `.pkg` 只安装自有 `.app` 到 `/Applications`，系统按正常流程申请管理员授权。手动用户目录安装不要求系统域安装权限。 |
| 用户数据 | 客户首次打开后才在 `~/Library/Application Support/HONGAI-Environment` 建立自有私有数据；加密配置仍绑定原用户与原目录，不移动或复制到另一个用户。 |
| Keychain | 加密存储可能触发系统钥匙串访问提示，应由客户确认；不把密码写进包，不预先代客户授权。 |
| 浏览器 | 本地 HTTP 回环地址，管理界面打开在默认浏览器，不强制 Chrome，不登录 Claude。 |
| 常驻 | 不安装 LaunchAgent、LoginItem、daemon、内核驱动、网络扩展。工作台服务仅在用户打开时运行，默认最长 120 分钟；浏览器关标签页不等于停止服务，使用工作台停止按钮。日常启动成功后管理入口可以退出。 |
| 其他权限 | 本安装器不要求屏幕录制、辅助功能、全磁盘访问、自动化控制其他应用或网络配置权限。官方 Claude 的 MCP/文件访问等权限由官方应用另行申请。 |
| 网络与远控 | 不修改 DNS、TUN、路由、Wi-Fi、Clash、系统代理或防火墙；不重启系统，不结束 ToDesk/Claude/Clash。 |

## 构建与静态核验（仅 Mac 构建机）

需要 Python 3 和 Apple 开发工具中的 `lipo`、`otool`、`iconutil`、`codesign`、`pkgbuild`、`productbuild`、`pkgutil`。这些都是**构建机依赖，客户无需安装**。无网络下载与账号要求。

```bash
export TMPDIR="$RUNNER_TEMP/hongai-mac-pkg-temp"
mkdir -p "$TMPDIR" "$RUNNER_TEMP/hongai-mac-output-parent"
export PYTHONDONTWRITEBYTECODE=1
bash release/mac-installer/build-mac-installer.sh \
  --runtime "$(pwd -P)/native-tools/dist/hongai-tools-universal" \
  --sha256 "<从已验证CI产物独立取得的64位SHA256>" \
  --icon "$(pwd -P)/release/brand-assets/HONGAI.icns" \
  --version 0.2.0 \
  --output "$RUNNER_TEMP/hongai-mac-output-parent/package-0.2.0"
bash release/mac-installer/verify-mac-installer.sh \
  --manifest "$RUNNER_TEMP/hongai-mac-output-parent/package-0.2.0/installer-manifest.json"
```

仓库在 CI 中若以其他子路径保存，调整上述脚本路径即可。输出必须是**尚不存在**的绝对目录；父目录必须存在且无符号链接。首次构建保留 `build-evidence`，失败不删除现场。构建产物与日志存放项目盘/CI 专用临时盘，不使用本机默认下载目录。

每个客户发布版本增加数值 `X.Y.Z`，不得用同一版本号替换不同内容。构建检查 universal 包同时包含 `arm64` 与 `x86_64`，从两架构真实 Mach-O deployment target 取更高的最低 macOS 版本，写入 `.app` 与 Installer 的系统要求，不凭空猜测最低兼容版本。

`.app` 最终签名会改变 Mach-O 字节：manifest 分别记录输入 runtime SHA-256 和最终 bundled runtime SHA-256。随后核验原 `.app`、ZIP 展开后的 `.app`、`.pkg` 展开后的 `.app` 与实际安装后的 `.app` 的最终字节、架构和完整性签名。输入 SHA-256 必须来自已验证、受信的 CI 交付记录，不能把未知来源包旁边的 manifest 当作独立信任依据。

原始下载保护标记在复制时保留；不执行任何 `xattr -d`。ad-hoc 签名只证明当前文件组合完整，不是发行方身份认证。`.pkg` 本身保持未签名，验证报告必须保留这一限制。

## 原生 CI 安装、升级与卸载验收

必须分别在 Apple Silicon 与 Intel 原生 macOS runner 执行。每种计划支持的 macOS 主版本都应独立跑原生 Go 测试和本包测试。跨编译成功和单一架构成功不能替代另一端安装验收。

```bash
# 只能在可销毁、无既有 HONG AI 安装/资料的 GitHub macOS runner 执行。
# 脚本同时要求 GITHUB_ACTIONS=true、明确标志、非root调用者。
bash release/mac-installer/ci-install-smoke.sh \
  --manifest "$RUNNER_TEMP/hongai-mac-output-parent/package-0.2.0/installer-manifest.json" \
  --disposable-ci
```

脚本先完整静态核验，再以当前 CI 用户建立独立 DataRoot 哨兵。通过 `sudo -n installer` 真正安装，读取实际安装文件运行 `version`，构建并安装递增数值版本核验升级，再将**仅自有已验证 `.app`**移动到恢复目录并清除该包收据。每阶段核对哨兵目录、用户与内容未变。不删除或搬走用户 DataRoot，不运行 `use`，不启动官方 Claude，不读取账号资料。

`ci-install-report.json` 出现 PASS 才能宣称此架构/系统的原生包安装、升级与自有应用可回滚卸载已通过。该 CI 验收**不覆盖**真实用户下载的 Gatekeeper 交互批准、正常图形登录、客户数据加密迁移、Claude 账号登录、对话、MCP 与文件下载，这些必须另行如实记录。Windows 本机只能运行本目录的纯逻辑单测，不能代替任何 Mac 原生结果。

## 升级、卸载与已知边界

- 更新前通过工作台停止控制停止 HONG AI 服务，然后再更新自有 `.app`；不结束代理与远控，不自动重启。安装器无 `postinstall`、`preinstall` 或其他安装脚本。
- `.pkg` 禁止重定位，只针对 `/Applications` 中相同 bundle identifier 的自有应用；开启 BundleVersionChecked 与严格 bundle identifier 检查。系统 Installer 的版本检查不是加密防降级；目前没有独立、不可篡改的防降级锚点，不承诺任意旧包都无法覆盖。发布渠道必须只提供最新已验证包。
- 官方 Claude 更新后依然从原签名 `.app` 重新发现并正常激活，不把旧版 Claude 安装包嵌进本包；未来官方改变 bundle identity/路径/签名时要重新适配验收，不能承诺任意未来更新自动兼容。
- 用户需要卸载时，先停止工作台，将自有 `.app` 移到废纸篓。卸载用户资料另用 runtime 的 `environment uninstall` 执行所有权核验与可恢复目录改名；不在 Finder 中误删 Claude、账户、工程或恢复文件。移动 `.app` 不会自动清除系统 `.pkg` 收据，可由管理员按本包精确 identifier 管理。
- 用户数据依赖原账户的 Keychain 与原目录，不能把安装包升级当作跨用户迁移。保留诊断日志、恢复目录与导出证据，不自动清理历史恢复。
- 目录是原生 `.app` 启动前端，不是内嵌原生 Cocoa 管理窗口：后台应用标志避免空 Dock 图标，工作台管理窗口在浏览器，官方 Claude 仍是官方 UI。未检测官方 Claude 或前置环境未确认时，只进行准备诊断，不代替客户登录。

验收记录应明确区分：`STATIC_VERIFICATION_PASS`、`NATIVE_PACKAGE_INSTALL_UPGRADE_RECOVERABLE_UNINSTALL_PASS`、客户交互验收与账号业务验收。不可将前两项写成「完整环境模拟已交付」或「保证账号稳定」。
