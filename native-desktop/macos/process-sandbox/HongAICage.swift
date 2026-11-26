import AppKit
import Foundation
import Darwin
import Network

// A session-owned endpoint, rather than Clash's reusable general port. Closing the
// supervisor closes every tunnel even if an approved tool outlives its parent.
final class SessionBroker {
    private let queue = DispatchQueue(label:"com.hongai.cage.session-broker")
    private let lock = NSLock()
    private var listener: NWListener?
    private var pairs: [UUID:(NWConnection,NWConnection)] = [:]
    private var validUntil = Date.distantPast
    private var stopped = false
    private let upstream: UInt16
    private(set) var port: UInt16 = 0
    init(upstream: UInt16) { self.upstream=upstream }
    func refresh() { lock.lock(); if !stopped {validUntil=Date().addingTimeInterval(12)}; lock.unlock() }
    func start() throws {
        let parameters=NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host:"127.0.0.1",port:.any)
        let server=try NWListener(using:parameters)
        let ready=DispatchSemaphore(value:0)
        var failure:NWError?
        server.stateUpdateHandler={ state in
            switch state {case .ready: self.port=server.port!.rawValue;ready.signal()
            case .failed(let error): failure=error;ready.signal()
            default: break}
        }
        server.newConnectionHandler={ [weak self] incoming in self?.accept(incoming) }
        listener=server; server.start(queue:queue)
        guard ready.wait(timeout:.now()+5) == .success, failure == nil, port > 1023 else {server.cancel();throw CageFailure("无法建立会话专用代理入口。")}
        refresh()
    }
    private func accept(_ incoming:NWConnection) {
        lock.lock();let admitted = !stopped && Date() < validUntil && pairs.count < 64;lock.unlock()
        guard admitted else {incoming.cancel();return}
        let outgoing=NWConnection(host:"127.0.0.1",port:NWEndpoint.Port(rawValue:upstream)!,using:.tcp)
        let key=UUID();lock.lock();pairs[key]=(incoming,outgoing);lock.unlock()
        func close(){self.lock.lock();let pair=self.pairs.removeValue(forKey:key);self.lock.unlock();pair?.0.cancel();pair?.1.cancel()}
        func pump(_ source:NWConnection,_ destination:NWConnection){
            source.receive(minimumIncompleteLength:1,maximumLength:65_536){data,_,complete,error in
                self.lock.lock();let allowed = !self.stopped && Date() < self.validUntil;self.lock.unlock()
                guard allowed,error == nil else {close();return}
                if let data=data,!data.isEmpty {destination.send(content:data,completion:.contentProcessed { sendError in if sendError != nil || complete {close()} else {pump(source,destination)} })}
                else if complete {close()} else {pump(source,destination)}
            }
        }
        outgoing.stateUpdateHandler={ state in
            if case .ready = state {incoming.start(queue:self.queue);pump(incoming,outgoing);pump(outgoing,incoming)}
            if case .failed = state {close()}
            if case .cancelled = state {close()}
        }
        incoming.stateUpdateHandler={ state in if case .failed = state {close()} }
        outgoing.start(queue:queue)
    }
    func stop(){
        lock.lock();stopped=true;validUntil = .distantPast;let active=Array(pairs.values);pairs.removeAll();lock.unlock()
        listener?.cancel();for pair in active {pair.0.cancel();pair.1.cancel()}
    }
    deinit {stop()}
}

func brokerSelfTest() throws {
    let queue=DispatchQueue(label:"com.hongai.cage.broker-proof"),ready=DispatchSemaphore(value:0)
    let params=NWParameters.tcp;params.requiredLocalEndpoint = .hostPort(host:"127.0.0.1",port:.any)
    let upstream=try NWListener(using:params)
    upstream.stateUpdateHandler={state in if case .ready = state {ready.signal()} }
    upstream.newConnectionHandler={connection in
        connection.stateUpdateHandler={state in if case .ready = state {
            connection.receive(minimumIncompleteLength:1,maximumLength:65_536){data,_,_,_ in
                connection.send(content:data,completion:.contentProcessed {_ in connection.cancel()})
            }
        }}
        connection.start(queue:queue)
    }
    upstream.start(queue:queue);defer{upstream.cancel()}
    guard ready.wait(timeout:.now()+4) == .success,let port=upstream.port else {throw CageFailure("BROKER_FIXTURE_START_FAILED")}
    let broker=SessionBroker(upstream:port.rawValue);try broker.start();defer{broker.stop()}
    func exchange()->Bool {
        let done=DispatchSemaphore(value:0),lock=NSLock();var matched=false
        let client=NWConnection(host:"127.0.0.1",port:NWEndpoint.Port(rawValue:broker.port)!,using:.tcp)
        let content=Data("hongai-owned-fixture".utf8)
        client.stateUpdateHandler={state in
            if case .failed = state {done.signal()}
            if case .ready = state {client.send(content:content,completion:.contentProcessed {error in
                if error != nil {done.signal();return}
                client.receive(minimumIncompleteLength:content.count,maximumLength:content.count){data,_,_,_ in lock.lock();matched=(data==content);lock.unlock();done.signal()}
            })}
        }
        client.start(queue:queue);_ = done.wait(timeout:.now()+4);client.cancel();lock.lock();let result=matched;lock.unlock();return result
    }
    guard exchange() else {throw CageFailure("BROKER_FORWARD_FAILED")};print("PASS session gateway forwards to selected local proxy")
    Thread.sleep(forTimeInterval:12.2)
    guard !exchange() else {throw CageFailure("BROKER_EXPIRED_LEASE_ACCEPTED")};print("PASS expired verification lease rejects new streams")
    broker.stop()
    guard !exchange() else {throw CageFailure("BROKER_STOP_ACCEPTED")};print("PASS stopped session gateway has no alternative route")
}

struct CageFailure: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

struct Handoff: Decodable {
    struct Loopback: Decodable { let `protocol`: String; let host: String; let mixedPort: Int }
    let version: Int
    let tool: String
    let loopback: Loopback
    let expectedEgressIp: String
    let routeId: String
    let generatedAt: String
    var proxy: String { "http://127.0.0.1:\(loopback.mixedPort)" }
    static func load(_ file: URL) throws -> Handoff {
        let data = try Data(contentsOf: file)
        guard data.count <= 16_384,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["version", "tool", "loopback", "expectedEgressIp", "routeId", "generatedAt"]),
              let loop = object["loopback"] as? [String: Any],
              Set(loop.keys) == Set(["protocol", "host", "mixedPort"]) else { throw CageFailure("交接文件格式不正确；不要导入含密码的订阅文件。") }
        let h = try JSONDecoder().decode(Handoff.self, from: data)
        let octets = h.expectedEgressIp.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4, octets.allSatisfy({ (0...255).contains($0) }),
              octets[0] > 0, octets[0] < 224, ![10,127].contains(octets[0]),
              !(octets[0] == 192 && octets[1] == 168),
              !(octets[0] == 172 && (16...31).contains(octets[1])),
              !(octets[0] == 169 && octets[1] == 254),
              !(octets[0] == 100 && (64...127).contains(octets[1])),
              h.version == 1, h.tool == "clash", h.loopback.host == "127.0.0.1",
              h.loopback.protocol == "http", (1024...65535).contains(h.loopback.mixedPort),
              h.routeId.range(of: "^[a-f0-9]{24}$", options: .regularExpression) != nil else { throw CageFailure("需要有效的 Clash 本地端口和最终公网 IPv4。") }
        let format = ISO8601DateFormatter()
        format.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let date = format.date(from: h.generatedAt) ?? ISO8601DateFormatter().date(from: h.generatedAt)
        guard let date = date, (-30...600).contains(Date().timeIntervalSince(date)) else { throw CageFailure("交接文件已过期，请重新生成（十分钟内有效）。") }
        return h
    }
}

enum CageRuntime {
    static func command(_ path: String, _ arguments: [String], timeout: TimeInterval = 12) throws -> String {
        let process = Process(), output = Pipe(), error = Pipe()
        process.executableURL = URL(fileURLWithPath: path); process.arguments = arguments
        process.environment = ["PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "LANG":"en_US.UTF-8"]
        process.standardOutput = output; process.standardError = error
        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if process.isRunning { kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw CageFailure("检查超时，保持断联。") }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0, data.count < 65_536 else { throw CageFailure("检查未通过：\(URL(fileURLWithPath:path).lastPathComponent)（\(process.terminationStatus)）") }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
    static func verifyExit(_ h: Handoff) throws {
        let observed = try command("/usr/bin/curl", ["--silent", "--show-error", "--fail", "--max-time", "8", "--noproxy", "", "--proxy", h.proxy, "--proto", "=https", "https://api.ipify.org"])
        guard observed == h.expectedEgressIp else { throw CageFailure("最终出口不一致，已阻止启动。") }
    }
    static func officialApp() throws -> URL {
        let paths = [URL(fileURLWithPath:"/Applications/Claude.app"), FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Claude.app")]
        guard let app = paths.first(where: { FileManager.default.fileExists(atPath:$0.path) }) else { throw CageFailure("请先安装 Anthropic 官方 Claude Desktop。") }
        let requirement = "anchor apple generic and identifier \"com.anthropic.claudefordesktop\" and certificate leaf[subject.OU] = \"Q6L2SF6YDW\""
        _ = try command("/usr/bin/codesign", ["--verify", "--deep", "--strict", "-R=" + requirement, app.path], timeout:30)
        return app.resolvingSymlinksInPath()
    }
    static func profile(port: Int, application: URL, home: URL) throws -> String {
        let deny = [application.path,
                    home.appendingPathComponent("Library/Application Support/Claude").path,
                    home.appendingPathComponent("Library/Application Support/Clash Verge").path,
                    home.appendingPathComponent("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev").path,
                    home.appendingPathComponent(".claude").path,
                    home.appendingPathComponent(".config/clash").path,
                    home.appendingPathComponent(".config/mihomo").path,
                    "/Library/Preferences/SystemConfiguration", "/private/etc/resolv.conf", "/private/etc/hosts"]
        for path in deny where path.contains("\"") || path.contains("\\") || path.contains("\n") || path.contains("\r") { throw CageFailure("路径包含不支持的字符。") }
        var result = "(version 1)\n(allow default)\n(deny network*)\n(allow network-outbound (remote tcp \"localhost:\(port)\"))\n(deny appleevent-send)\n"
        result += "(deny mach-lookup (global-name \"com.apple.nsurlsessiond\") (global-name \"com.apple.lsd.open\"))\n"
        for path in deny.dropFirst() { result += "(deny file-read* file-write* (subpath \"\(path)\"))\n" }
        result += "(deny file-write* (subpath \"\(application.path)\"))\n"
        return result
    }
}

final class CageController: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    let status = NSTextField(wrappingLabelWithString:"导入第一步交接文件，选择工作文件夹，再启动官方桌面版。")
    let fileLabel = NSTextField(labelWithString:"未选择交接文件")
    let workspaceLabel = NSTextField(labelWithString:"未选择工作文件夹")
    let start = NSButton(title:"启动 Claude 桌面版", target:nil, action:nil)
    var handoffURL: URL?, workspace: URL?, process: Process?, timer: Timer?
    var broker: SessionBroker?
    var busy = false, generation = UUID()

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect:NSRect(x:0,y:0,width:650,height:430), styleMask:[.titled,.closable,.miniaturizable], backing:.buffered, defer:false)
        window.title = "HONG AI CAGE · 桌面进程隔离测试版"; window.center()
        let content = NSStackView(); content.orientation = .vertical; content.alignment = .leading; content.spacing = 18; content.edgeInsets = NSEdgeInsets(top:28,left:30,bottom:28,right:30)
        let brand = NSTextField(labelWithString:"HONG AI  /  CAGE")
        brand.font = .systemFont(ofSize:27,weight:.bold); brand.textColor = NSColor(calibratedRed:0.7,green:0.05,blue:0.12,alpha:1)
        let subtitle = NSTextField(labelWithString:"官方桌面程序 · 指定代理端口 · 独立登录数据")
        subtitle.textColor = .secondaryLabelColor
        let choose = NSButton(title:"① 选择交接文件",target:self,action:#selector(chooseHandoff))
        let folder = NSButton(title:"② 选择工作文件夹",target:self,action:#selector(chooseWorkspace))
        start.target = self; start.action = #selector(startSession); start.bezelStyle = .rounded
        let stop = NSButton(title:"停止隔离会话",target:self,action:#selector(stopSession))
        let actions = NSStackView(views:[start,stop]); actions.spacing = 18
        let note = NSTextField(wrappingLabelWithString:"保留现有 Clash、Wi-Fi 和远控设置。仅本进程树受限；外部浏览器登录、Cowork 和系统集成尚未验收。")
        note.font = .systemFont(ofSize:12); note.textColor = .secondaryLabelColor
        for view in [brand,subtitle,choose,fileLabel,folder,workspaceLabel,actions,status,note] { content.addArrangedSubview(view) }
        content.translatesAutoresizingMaskIntoConstraints = false; window.contentView!.addSubview(content)
        NSLayoutConstraint.activate([content.leadingAnchor.constraint(equalTo:window.contentView!.leadingAnchor),content.trailingAnchor.constraint(equalTo:window.contentView!.trailingAnchor),content.topAnchor.constraint(equalTo:window.contentView!.topAnchor)])
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps:true)
    }
    @objc func chooseHandoff() { let panel=NSOpenPanel(); panel.canChooseDirectories=false; panel.allowsMultipleSelection=false; if panel.runModal() == .OK { handoffURL=panel.url; fileLabel.stringValue=panel.url!.lastPathComponent } }
    @objc func chooseWorkspace() { let panel=NSOpenPanel(); panel.canChooseDirectories=true; panel.canChooseFiles=false; if panel.runModal() == .OK { workspace=panel.url?.resolvingSymlinksInPath(); workspaceLabel.stringValue=workspace!.path } }
    func message(_ text:String) { DispatchQueue.main.async { self.status.stringValue=text } }
    @objc func startSession() {
        guard !busy, process == nil else { return }
        guard let file=handoffURL, let workspace=workspace else { status.stringValue="请先选择交接文件和工作文件夹。"; return }
        guard workspace.path != "/", workspace != FileManager.default.homeDirectoryForCurrentUser else { status.stringValue="请选择具体项目文件夹。"; return }
        busy=true; start.isEnabled=false; generation=UUID(); let token=generation
        message("核验官方签名与最终出口……")
        DispatchQueue.global(qos:.userInitiated).async {
            do {
                guard NSRunningApplication.runningApplications(withBundleIdentifier:"com.anthropic.claudefordesktop").isEmpty else { throw CageFailure("请先退出正在运行的 Claude。") }
                let h=try Handoff.load(file), app=try CageRuntime.officialApp()
                for _ in 0..<3 { try CageRuntime.verifyExit(h) }
                let home=FileManager.default.homeDirectoryForCurrentUser
                let root=home.appendingPathComponent("Library/Application Support/HONGAI-CAGE-Desktop")
                try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
                let ownProfile=root.appendingPathComponent("profile"), temp=root.appendingPathComponent("temp")
                for item in [ownProfile,temp] { try FileManager.default.createDirectory(at:item,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]) }
                let broker=SessionBroker(upstream:UInt16(h.loopback.mixedPort));try broker.start()
                let sessionProxy="http://127.0.0.1:\(broker.port)"
                let policy=root.appendingPathComponent("boundary.sb")
                try CageRuntime.profile(port:Int(broker.port),application:app,home:home).write(to:policy,atomically:true,encoding:.utf8)
                let p=Process(); p.executableURL=Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/CageSession")
                p.arguments=["/usr/bin/sandbox-exec","-f",policy.path,app.appendingPathComponent("Contents/MacOS/Claude").path,"--user-data-dir=\(ownProfile.path)","--proxy-server=\(sessionProxy)","--proxy-bypass-list=<-loopback>","--disable-quic"]
                p.currentDirectoryURL=workspace
                p.environment=["PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin","HOME":root.path,"TMPDIR":temp.path,"HTTP_PROXY":sessionProxy,"HTTPS_PROXY":sessionProxy,"ALL_PROXY":sessionProxy,"NO_PROXY":"","LANG":"en_US.UTF-8"]
                p.standardOutput=FileHandle.nullDevice; p.standardError=FileHandle.nullDevice
                DispatchQueue.main.async {
                    do {
                        guard self.generation == token else {broker.stop();return}
                        try p.run(); self.process=p;self.broker=broker;self.busy=false
                        p.terminationHandler={ _ in DispatchQueue.main.async { if self.process === p { self.stopSession(); self.status.stringValue="桌面进程已退出。" } } }
                        self.status.stringValue="隔离会话运行中；指定出口 \(h.expectedEgressIp)。"
                        self.timer=Timer.scheduledTimer(withTimeInterval:4,repeats:true) { _ in self.verifyRunning(h,token:token) }
                    } catch {broker.stop();self.busy=false;self.start.isEnabled=true;self.status.stringValue="启动失败：\(error)"}
                }
            } catch { DispatchQueue.main.async { self.busy=false; self.start.isEnabled=true; self.status.stringValue="未启动：\(error)" } }
        }
    }
    func verifyRunning(_ h:Handoff,token:UUID) {
        guard !busy else { return }; busy=true
        DispatchQueue.global(qos:.utility).async {
            do {try CageRuntime.verifyExit(h);DispatchQueue.main.async {if self.generation == token {self.broker?.refresh()};self.busy=false}}
            catch { DispatchQueue.main.async { if self.generation == token { self.stopSession(); self.status.stringValue="代理不可用或出口变化，会话已停止。" } } }
        }
    }
    @objc func stopSession() {
        generation=UUID(); timer?.invalidate(); timer=nil
        broker?.stop();broker=nil
        if let p=process, p.isRunning {kill(-p.processIdentifier,SIGKILL);kill(p.processIdentifier,SIGKILL)}
        process=nil; busy=false; start.isEnabled=true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication)->Bool {true}
    func applicationWillTerminate(_ notification:Notification) {stopSession()}
}

if CommandLine.arguments.contains("--broker-self-test") {
    do {try brokerSelfTest();exit(0)} catch {fputs("\(error)\n",stderr);exit(1)}
}
if CommandLine.arguments.contains("--verify-policy") || CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--emit-policy" {
    do {
        let home=FileManager.default.homeDirectoryForCurrentUser
        let port=CommandLine.arguments.count == 4 ? Int(CommandLine.arguments[2]) ?? 0 : 17896
        guard (1024...65535).contains(port) else {throw CageFailure("INVALID_SESSION_PORT")}
        let app=CommandLine.arguments.count == 4 ? CommandLine.arguments[3] : "/Applications/Claude.app"
        let policy=try CageRuntime.profile(port:port,application:URL(fileURLWithPath:app),home:home)
        print(policy)
        exit(0)
    } catch { fputs("\(error)\n",stderr); exit(1) }
}
let application=NSApplication.shared
let delegate=CageController()
application.delegate=delegate
application.setActivationPolicy(.regular)
application.run()
