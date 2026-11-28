# Windows 每用户 MSI 构建与验收

范围：HONG AI 环境工作台的普通安装体验，准备与诊断组件验证版。此目录不修改 Go 源码。安装 MSI、真实升级及卸载测试只在一次性 GitHub Hosted Windows Runner 执行，本机只构建和读取 MSI。Mac 独立实现与验证，Windows 证据不可代替 Mac。

## 构建工具

采用 Windows 自带 `makecab.exe` 及 `WindowsInstaller.Installer` Automation。无需向客户安装 PowerShell、Python、Go、.NET 或 WiX；这些脚本仅供发行构建及 CI。构建脚本用 PowerShell 7 执行。支持已独立执行原生测试并绑定哈希的控制台或 windowsgui EXE；PE Subsystem 必须分别精确为3或2。0.2.1新发行使用windowsgui，旧版升级夹具使用console；两份实际EXE均完整测试。

WiX 官方 NuGet 最新系列需要 .NET 工具运行时，并对营收用户说明维护费条款；本实现不安装或使用 WiX。依据：[Windows Installer Database Automation](https://learn.microsoft.com/en-us/windows/win32/msi/database-object)、[SummaryInformation](https://learn.microsoft.com/en-us/windows/win32/msi/database-summaryinformation)、[Installer.FileHash](https://learn.microsoft.com/en-us/windows/win32/msi/installer-filehash)、[每用户无需 UAC 的包](https://learn.microsoft.com/en-us/windows/win32/msi/authoring-packages-without-the-uac-dialog-box)、[ICE38 用户目录组件 HKCU KeyPath](https://learn.microsoft.com/en-us/windows/win32/msi/ice38)、[MSI 命令行](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options)、[升级事务时机](https://docs.firegiant.com/wix/schema/wxs/majorupgrade/)、[WiX 发行来源及条款](https://www.nuget.org/packages/wix)。

## 根 CI 调用接口

构建两份已经分别经过对应源快照原生测试的不同 payload。可以使用上一个验证版本为 old、本次验证版本为 new；只改变编译元数据而不测试其实际文件，不满足证据要求。两个 MSI ProductVersion 必须严格递增，如 `0.2.0`、`0.2.1`，UpgradeCode 固定，新 ProductCode 自动生成。

每份 payload 的验证 JSON 必须精确匹配：

```json
{
  "schema": "hongai.windows-payload-validation.v1",
  "sha256": "对应已独立验证EXE的64位小写SHA256",
  "sourceCommit": "对应已验证源码的40位小写commit",
  "nativeTestsPassed": true,
  "cliSmokePassed": true,
  "executableMode": "windowsgui"
}
```

`cliSmokePassed` 应由该实际 EXE 的 `version` 命令以及已有环境 CLI 生命周期测试取得，不因另一个子系统或文件名版本通过就移植证明。原生测试计数跟平台真实输出走，不强行对齐。先完成 Go 原生测试并保存证据，再创建这个绑定 JSON。

```powershell
# 供根 CI 集成的 pwsh 步骤；$Old/$New 是前面已下载并核验的 artifact。
$Build = Join-Path $PSScriptRoot 'Build-PerUserMsi.ps1'
$license = Join-Path (& go env GOROOT) 'LICENSE'
# 所有 build 输出和 TEMP/TMP 都放 D:；github hosted runner 上 D: 可用。
$out = 'D:\hongai-msi-ci'
& $Build -PayloadFile $Old.Exe -ExpectedSHA256 $Old.Hash `
  -SourceCommit $Old.Commit -ProductVersion '0.2.0' `
  -LicenseFile $license -OutputDirectory "$out\old" `
  -PayloadValidationJson $Old.ValidationJson -IconFile $BrandIcon
& $Build -PayloadFile $New.Exe -ExpectedSHA256 $New.Hash `
  -SourceCommit $New.Commit -ProductVersion '0.2.1' `
  -LicenseFile $license -OutputDirectory "$out\new" `
  -PayloadValidationJson $New.ValidationJson -IconFile $BrandIcon
& (Join-Path $PSScriptRoot 'Test-PerUserMsi.ps1') `
  -OldMsi "$out\old\HONGAI-Environment-Workbench-0.2.0-x64.msi" `
  -NewMsi "$out\new\HONGAI-Environment-Workbench-0.2.1-x64.msi" `
  -OutputDirectory "$out\validation"
```

CI runner 推荐分别 `windows-2022` 和 `windows-2025`。必须是 `GITHUB_ACTIONS=true`、`RUNNER_OS=Windows`、`RUNNER_ENVIRONMENT=github-hosted` 的一次性干净机器；不要在开发机/客户机器伪造这些变量。MSI 安装路径是 CI 机器的每用户 Programs 系统目录；本机不运行 `msiexec`，本机项目产物只放 D/E。

## 验证内容与留存

`Test-PerUserMsi.ps1` 检查结构无 CustomAction/服务/环境变量等修改表，确认每用户包和事务内旧版移除、无 REINSTALLMODE 强制覆盖、无版本文件有 MsiFileHash；实际安装 old，核对真实 SHA 和无参数稳定快捷方式。Go 创建私有 owner 后再写哨兵和受保护测试配置，启动独立私有运行时管理进程；运行中升级至不同 new SHA，拒绝旧版降级，卸载新版后检查安装文件/快捷方式消失，私有配置、哨兵、已有管理进程及无关对照进程仍保留。最后只关闭明确记录 PID 的测试进程。

`msiexec /qn /norestart /L*v` 强制不重启；遇到 3010 需要重启时不标记通过。MSI 本身不注册服务，不安装驱动，不写系统网络，无权替代理工具提供原生全流量防护。

可收集 MSI、manifest、`MSI-VALIDATION.json`、四类 MSI 日志。**不要收集整个 `%LOCALAPPDATA%`、私有根、sealed 文件或 workbench-address；测试期间的本地会话令牌只存在内存。** 不执行账号登录，不读取 Claude 个人资料。未测试正式代码签名/组织策略、真实用户 Claude 登录、长时间运行、重启及真实 ToDesk 会话；这些不得冒称通过。

当前安装器生成包未做组织代码签名，也尚未执行 Windows SDK 的完整 ICE 验证。静态结构检查和实际 msiexec 生命周期验收不能冒充完整认证。构建 smoke 文件夹保留调试证据，不能当作最新客户发行包。
