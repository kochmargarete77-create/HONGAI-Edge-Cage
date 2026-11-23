# HONG AI Edge Cage

HONG AI Edge Cage 是面向官方 Claude Code CLI 的跨平台故障封闭隔离与交付控制器。

本项目基于 [ClaudeCage](https://github.com/PACHAKUTlQ/ClaudeCage) 二次开发。当前受支持的 Alpha 交付路径面向 Windows 与 macOS，使用 Anthropic Sandbox Runtime、客户授权的 Clash 链式代理和最终出口持续校验；上游 Linux 便携后端仅作为实验兼容模式保留，不属于 HONG AI 客户验收路径。

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
- 仅回环可访问的 HONG AI 控制台、出口核验与防篡改审计时间线。
- 公共核心 + GitHub Release 加密制品 + 长期授权 + 单次令牌的受控交付协议。
- 跨进程授权存储锁、幂等单调回执状态机，以及不在磁盘明文保存回执令牌的加密可重试 outbox。
- 验签领取、防碰撞安全解包、staging 优先的平台安装脚本和失败清理。
- 绑定 commit/tree/blob/hash 构建记录的确定性源码发布构建器；在 Windows 上强制输出到 D:/E: 数据盘。
- 宿主环境变量白名单与独立 AppData/XDG/npm/Git/GnuPG 状态，降低软件身份泄漏。

## 核心不变量

本地代理不可用、最终 IPv4 缺失或不一致、平台不一致、系统时区不一致时，官方 Claude Code 不启动。运行中最终出口消失或变化时，会话被终止。生成的 Claude 路由组没有直连回退。

## 当前状态

`0.2.0-alpha.3` 是可测试的开发里程碑，还不是已经签名的客户安装包。部署前请阅读 [部署说明](docs/DEPLOYMENT.md)、[架构](docs/ARCHITECTURE.md)、[安全模型](docs/SECURITY-MODEL.md)、[隔离等级](docs/ISOLATION-TIERS.md)、[受控交付协议](docs/SECURE-DELIVERY.md)、[授权服务运维](docs/LICENSE-SERVICE.md)、[发布准备](docs/RELEASE-PROCESS.md) 和 [验收矩阵](docs/ACCEPTANCE-MATRIX.md)。

本项目不是 Anthropic 产品、认证或官方评分。每位终端用户通过未修改的官方 Claude Code 流程使用自己控制的账号完成认证。
