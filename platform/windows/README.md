# Windows 离线试点交付

客户机安装阶段不访问 npm registry，也不执行 `npm ci` 或 TypeScript 编译。交付包必须在构建机完成依赖安装与编译，并至少包含：

```text
package/
  dist/
  node_modules/
  runtime/node.exe
  platform/windows/
  package.json
  HONGAI-DELIVERY.json
  HONGAI-PAYLOAD.json
```

客户机不会下载 Node.js，也不会用系统 Node.js 替代固定的 `runtime/node.exe`。安装器会在提权改机前逐文件核对 `HONGAI-PAYLOAD.json` 的大小和 SHA-256，并拒绝未声明文件、重解析点、平台或架构不匹配。

## 安装

安装目录和客户配置必须位于 D: 或 E: 数据盘。在管理员 PowerShell 中运行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
& E:\HONGAI\Edge-Cage\platform\windows\Install-HONGAI-Edge-Cage.ps1 `
  -ConfigPath E:\HONGAI\customer.yaml
```

安装器依次完成：管理员权限、数据盘、架构、固定运行时、交付清单、离线依赖、3 GiB 空间和配置校验；随后检查是否已有机器级 Sandbox Runtime。全新安装由 Edge Cage 持有并可自动回滚；已有安装默认只验证、不修改，避免破坏其他软件。安装状态会绑定已经验收的客户配置 SHA-256，启动时不能悄悄换成另一份配置。

程序、配置、日志和客户状态均留在 D: 或 E:。唯一不可避免的系统盘/系统级变更来自 Windows 沙箱本身：专用本地账号、凭据、权限和 WFP 过滤器；安装状态会记录其所有权，便于精确回滚。

只有明确确认没有其他软件依赖现有 Sandbox Runtime 时，才允许：

```powershell
& .\Install-HONGAI-Edge-Cage.ps1 -ConfigPath E:\HONGAI\customer.yaml -AllowSharedSandboxUpgrade
```

安装完成前必须通过 `doctor`：本地代理、最终出口、时区、沙箱文件隔离和直接联网阻断任一失败都会中止。全新机器上的失败会自动撤销专用账号与 WFP 规则。

安装器会在首次机器级变更前原子写入 `INSTALLING` 所有权记录。若安装期间断电或进程被强制终止，不要删除或手工改写 `.edge-cage\windows-install-state.json`：从同一版本目录以管理员身份运行卸载器。记录证明安装开始前没有 SRT/WFP 时，卸载器会回收本次安装可能留下的状态；记录证明沙箱原本已存在时，卸载器只分离本应用并保留共享状态。损坏或未知记录一律拒绝猜测性删除。恢复完成后，由操作员审计并移走停用的版本目录，再重新领取/恢复安装。

## 复检与启动

```powershell
& .\Test-HONGAI-Edge-Cage.ps1 -ConfigPath E:\HONGAI\customer.yaml
& .\Start-HONGAI-Edge-Cage.ps1 -ConfigPath E:\HONGAI\customer.yaml
```

启动器仍会再次执行故障封闭出口预检；出口不一致时不会启动 Claude Code。

## 卸载与所有权

```powershell
& .\Uninstall-HONGAI-Edge-Cage.ps1
```

安装状态记录 Sandbox Runtime 是否由本次 Edge Cage 安装创建。只有本次安装持有的机器级账号/WFP 才会被默认移除；已有共享安装会保留。强制移除共享运行时必须显式加 `-RemoveSharedSandbox`，并会影响所有依赖它的软件。

客户工作区和隔离 Agent 状态不由卸载器删除，便于审计和恢复；后续数据清理应单独确认目标路径。脚本也不会在运行中自删安装目录；审计完成后，可由外层部署器或管理员单独移除已经停用的程序目录。
