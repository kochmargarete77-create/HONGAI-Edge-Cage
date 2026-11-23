# HONG AI Edge Cage

HONG AI Edge Cage 是面向官方 Claude Code CLI 的跨平台故障封闭隔离与交付控制器。

本项目基于 [ClaudeCage](https://github.com/PACHAKUTlQ/ClaudeCage) 二次开发。上游 Linux 便携后端作为兼容模式保留；新的默认架构使用 Anthropic Sandbox Runtime 覆盖 Windows、macOS 与 Linux，并叠加客户授权的 Clash 链式代理和最终出口持续校验。

## 当前 Alpha 能力

- 严格客户 YAML 配置。
- 固定版本的官方 Claude Code 与沙箱运行时。
- 全进程树的文件系统和网络隔离。
- 每个环境独立的 HOME、USERPROFILE 与 CLAUDE_CONFIG_DIR。
- 目标域名白名单、私网/回环/链路本地地址拒绝。
- 通过本地回环代理接入客户 Clash。
- 可重复导入、没有 DIRECT 回退的 Clash.Meta 全局脚本。
- 启动前连续出口检查和运行中出口看门狗。
- Windows WFP 安装/卸载脚本与 macOS Seatbelt 启动脚本。
- HONG AI 产品硬门槛验收矩阵。
- 将少量前置节点和最终出口参数自动展开为完整严格策略的客户参数编译器。

## 核心不变量

本地代理不可用、最终 IPv4 缺失或不一致、平台不一致、系统时区不一致时，官方 Claude Code 不启动。运行中最终出口消失或变化时，会话被终止。生成的 Claude 路由组没有直连回退。

## 当前状态

`0.1.0-alpha.1` 是可测试的开发里程碑，还不是已经签名的客户安装包。部署前请阅读 [部署说明](docs/DEPLOYMENT.md)、[架构](docs/ARCHITECTURE.md)、[安全模型](docs/SECURITY-MODEL.md) 和 [验收矩阵](docs/ACCEPTANCE-MATRIX.md)。

本项目不是 Anthropic 产品、认证或官方评分。每位终端用户通过未修改的官方 Claude Code 流程使用自己控制的账号完成认证。
