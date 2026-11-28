# HONG AI 环境仿真实验内核

本目录实现授权测试用的统一环境模型、本地 metadata provider 与独立子进程读回。它是尚未接入厂商测试接口的研发原型，不能当作官方客户端已使用模拟设备信息的证明。

现有客户工作台 0.3.0 保持原样。本实验不修改官方程序、真实硬件标识、系统设置、Clash、登录资料或客户发送区，不联系任何线上服务。

## 运行

在项目盘的本目录执行：

```powershell
node ci-validate.mjs
node demo.mjs --provider local_mock --profile fixtures/windows-x64.json
node demo.mjs --provider local_mock --profile fixtures/macos-arm64.json
node demo.mjs --provider local_mock --profile fixtures/macos-x64.json
```

`demo` 输出只到终端。`ci-validate` 将测试证据写入本目录的 `out`，测试临时文件写入本目录的 `tmp`；Windows 要求项目位于 D/E。没有 npm 依赖、自动上传或写入系统用户目录的步骤。CI 下载明确指定版本的 Node，仅运行本地模型测试。

## 稳定身份、版本与容量

首次创建后用同一存储目录重开，无需重新提交模型。模型身份固定，更新必须显式提高修订号；单次会话锁定完整快照，七类观察面不会混用新旧版本。

```powershell
node session.mjs --provider local_mock --store E:\codexdata\hongai-lab-session --profile fixtures/windows-x64.json
node session.mjs --provider local_mock --store E:\codexdata\hongai-lab-session
```

macOS 使用项目卷上已解析的绝对路径。存储仅接管自己创建的文件，原子提交 HEAD 并保留上一版本。损坏记录、未完成提交和未知文件保留供复核；不自动重建为成功，不删除客户文件。最多 256 个模型快照、16 MiB 已知存储文件；达到上限后拒绝继续写入。Windows 断电耐久性未验收，原子提交测试不等于断电或整机重启测试。

并发锁用于合作进程间协调，不是同用户恶意进程的安全隔离边界。未实现真实系统身份变更或对正式软件的采集 API 替换。

## 实现层与验收层

模型覆盖 network、regional、platform、hardware、rendering、state、tools 七类观察面。同一配置规范化后保持稳定摘要；不依据 IP 推断国籍、收入或硬件消费偏好。硬件字段是有约束的合成测试数据，不会改变实际 CPU 指令、GPU 执行能力或物理设备标识。

子进程不接收模型文件、预期答案或含答案的环境变量。它通过固定协议向本地 provider 请求各观察面。每次运行使用新 challenge、运行标识、实际 PID、代码摘要和有界消息；超时、旧 challenge、输出超限或读回不符均失败，不用预期值补成成功。

结果固定记录 `LOCAL_SIMULATOR_READBACK`、`local_mock`、`officialClientConnected=false`、`targetServiceContacted=false`、`nativeHardwareReadPathsValidated=false` 和 `customerReady=false`。在 Windows 上读回 Mac 模型只是跨模型测试，不能当作 Mac 系统实测。

## 接入厂商测试客户端需要的输入

下一层需要你所获授权范围内的测试 SDK、专用测试构建或公开的接入契约，包括支持的系统/架构、接口版本、目标进程与 helper/工具进程清单、允许替换的读取面和实际读回方式。不需要账号密码、证书私钥或联系人信息。

没有对应连接器时返回 `NOT_CONNECTED`，不能静默换成 local mock，也不调整正式客户端的验签规则。接入后的证据应独立升级为厂商适配器读回、指定目标客户端读回；前两层模型与样例测试不替代后两层。

当前仍未接入真实系统信息 API、固件、CPU 指令、IOKit、Metal/Direct3D 执行、受保护硬件证明或官方客户端的采集链。所有这些缺口必须按具体版本和读取路径列出，不能因模型返回一致便宣称全面完成。
