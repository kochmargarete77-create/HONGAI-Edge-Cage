import AppKit
import Foundation
import Darwin
import Network
import CryptoKit

enum ProxyDestinationPolicy {
    static func publicIPv4(_ b:[UInt8])->Bool {
        b.count == 4 && b[0] > 0 && b[0] < 224 && b[0] != 10 && b[0] != 127 &&
        !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && (16...31).contains(b[1])) &&
        !(b[0] == 192 && b[1] == 168) && !(b[0] == 100 && (64...127).contains(b[1])) &&
        !(b[0] == 198 && (b[1] == 18 || b[1] == 19))
    }
    static func permits(_ line:String)->Bool {
        let parts=line.split(separator:" ",omittingEmptySubsequences:false)
        guard parts.count == 3,parts[0] == "CONNECT",["HTTP/1.0","HTTP/1.1"].contains(String(parts[2])) else {return false}
        let authority=String(parts[1])
        guard authority.count < 4096,!authority.contains(where:{"@/\\?#%".contains($0)||$0.isWhitespace}),
              let c=URLComponents(string:"https://"+authority),c.user == nil,c.password == nil,c.query == nil,c.fragment == nil,
              c.path == "" || c.path == "/",let port=c.port,(1...65535).contains(port),let value=c.host else {return false}
        let host=value.trimmingCharacters(in:CharacterSet(charactersIn:"[]")).lowercased()
        var four=in_addr()
        if host.withCString({inet_aton($0,&four)}) == 1 {return publicIPv4(withUnsafeBytes(of:&four){Array($0)})}
        var six=in6_addr()
        if host.withCString({inet_pton(AF_INET6,$0,&six)}) == 1 {
            let bytes=withUnsafeBytes(of:&six){Array($0)}
            if bytes.prefix(10).allSatisfy({$0==0}) && bytes[10] == 255 && bytes[11] == 255 {return publicIPv4(Array(bytes.suffix(4)))}
            return bytes[0]&0xE0 == 0x20
        }
        let domain=host.trimmingCharacters(in:CharacterSet(charactersIn:"."))
        guard domain.contains("."),domain.count <= 253,domain.allSatisfy({$0.isASCII && ($0.isLetter||$0.isNumber||$0=="-"||$0==".")}) else {return false}
        return ![".localhost",".local",".internal",".lan",".home",".arpa"].contains(where:{domain.hasSuffix($0)})
    }
}

// A session-owned endpoint, rather than Clash's reusable general port. Closing the
// supervisor closes every tunnel even if an approved tool outlives its parent.
final class SessionBroker {
    private let queue = DispatchQueue(label:"com.hongai.cage.session-broker")
    private let lock = NSLock()
    private var listener: NWListener?
    private var pairs: [UUID:(NWConnection,NWConnection)] = [:]
    private var validUntil:UInt64 = 0
    private var stopped = false
    private let upstream: UInt16
    private(set) var port: UInt16 = 0
    init(upstream: UInt16) { self.upstream=upstream }
    func refresh() { lock.lock(); if !stopped {validUntil=DispatchTime.now().uptimeNanoseconds+12_000_000_000}; lock.unlock() }
    func start() throws {
        let parameters=NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host:"127.0.0.1",port:.any)
        let server=try NWListener(using:parameters)
        let ready=DispatchSemaphore(value:0)
        var failure:NWError?
        server.stateUpdateHandler={ [weak self,weak server] state in
            switch state {case .ready: guard let server=server else {return};self?.port=server.port!.rawValue;ready.signal()
            case .failed(let error): failure=error;ready.signal()
            default: break}
        }
        server.newConnectionHandler={ [weak self] incoming in guard let owner=self else {incoming.cancel();return};owner.accept(incoming) }
        listener=server; server.start(queue:queue)
        guard ready.wait(timeout:.now()+5) == .success, failure == nil, port > 1023 else {server.cancel();throw CageFailure("无法建立会话专用代理入口。")}
        refresh()
    }
    private func accept(_ incoming:NWConnection) {
        lock.lock();let admitted = !stopped && DispatchTime.now().uptimeNanoseconds < validUntil && pairs.count < 64;lock.unlock()
        guard admitted else {incoming.cancel();return}
        let outgoing=NWConnection(host:"127.0.0.1",port:NWEndpoint.Port(rawValue:upstream)!,using:.tcp)
        let key=UUID();lock.lock();pairs[key]=(incoming,outgoing);lock.unlock()
        func close(){self.lock.lock();let pair=self.pairs.removeValue(forKey:key);self.lock.unlock();pair?.0.stateUpdateHandler=nil;pair?.1.stateUpdateHandler=nil;pair?.0.cancel();pair?.1.cancel()}
        func pump(_ source:NWConnection,_ destination:NWConnection){
            source.receive(minimumIncompleteLength:1,maximumLength:65_536){data,_,complete,error in
                self.lock.lock();let allowed = !self.stopped && DispatchTime.now().uptimeNanoseconds < self.validUntil;self.lock.unlock()
                guard allowed,error == nil else {close();return}
                if let data=data,!data.isEmpty {destination.send(content:data,completion:.contentProcessed { sendError in if sendError != nil || complete {close()} else {pump(source,destination)} })}
                else if complete {close()} else {pump(source,destination)}
            }
        }
        var header=Data()
        func readHeader(){
            incoming.receive(minimumIncompleteLength:1,maximumLength:4096){data,_,complete,error in
                self.lock.lock();let valid = !self.stopped && DispatchTime.now().uptimeNanoseconds < self.validUntil;self.lock.unlock()
                guard valid,error == nil,let data=data,!data.isEmpty else {close();return}
                header.append(data)
                guard header.count <= 16384 else {close();return}
                if header.range(of:Data("\r\n\r\n".utf8)) != nil {
                    let line=String(decoding:header,as:UTF8.self).components(separatedBy:"\r\n")[0]
                    guard ProxyDestinationPolicy.permits(line) else {close();return}
                    outgoing.start(queue:self.queue)
                }else if complete {close()}else{readHeader()}
            }
        }
        outgoing.stateUpdateHandler={ state in
            if case .ready = state {outgoing.send(content:header,completion:.contentProcessed {error in if error != nil {close()}else{pump(incoming,outgoing);pump(outgoing,incoming)}})}
            if case .failed = state {close()}
            if case .cancelled = state {close()}
        }
        incoming.stateUpdateHandler={ state in if case .failed = state {close()};if case .ready = state {readHeader()} }
        incoming.start(queue:queue)
    }
    func stop(){
        lock.lock();stopped=true;validUntil=0;let active=Array(pairs.values);pairs.removeAll();lock.unlock()
        listener?.cancel();for pair in active {pair.0.stateUpdateHandler=nil;pair.1.stateUpdateHandler=nil;pair.0.cancel();pair.1.cancel()}
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
        let content=Data("CONNECT fixture.example:443 HTTP/1.1\r\nHost: fixture.example:443\r\n\r\n".utf8)
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
    for target in ["127.0.0.1:9090","[::1]:9090","169.254.169.254:80","2130706433:80","10.0.0.1:80","metadata.google.internal:80","user@fixture.example:443"] {
        guard !ProxyDestinationPolicy.permits("CONNECT \(target) HTTP/1.1") else {throw CageFailure("PRIVATE_DESTINATION_ACCEPTED")}
        print("PASS local/metadata destination rejected \(target)")
    }
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
    static func load(_ file: URL,requireFresh:Bool=true) throws -> Handoff {
        return try decode(Data(contentsOf:file),requireFresh:requireFresh)
    }
    static func decode(_ data:Data,requireFresh:Bool=true) throws -> Handoff {
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
        guard let date = date, Date().timeIntervalSince(date) >= -30, !requireFresh || Date().timeIntervalSince(date) <= 600 else { throw CageFailure("交接文件已过期，请重新生成（十分钟内有效）。") }
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
        if CommandLine.arguments.contains("--daily-launch-smoke-test"),ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",ProcessInfo.processInfo.environment["RUNNER_OS"] == "macOS" {return}
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
                    home.appendingPathComponent("Library/Application Support/Google/Chrome").path,
                    home.appendingPathComponent("Library/Application Support/Microsoft Edge").path,
                    home.appendingPathComponent(".config/clash").path,
                    home.appendingPathComponent(".config/mihomo").path,
                    "/Library/Preferences/SystemConfiguration", "/private/etc/resolv.conf", "/private/etc/hosts"]
        let wrapper=Bundle.main.bundleURL.path
        for path in deny+[wrapper] where path.contains("\"") || path.contains("\\") || path.contains("\n") || path.contains("\r") { throw CageFailure("路径包含不支持的字符。") }
        var result = "(version 1)\n(allow default)\n(deny network*)\n(allow network-outbound (remote tcp \"localhost:\(port)\"))\n(deny appleevent-send)\n"
        result += "(deny mach-lookup (global-name \"com.apple.nsurlsessiond\") (global-name \"com.apple.lsd.open\"))\n"
        for path in deny.dropFirst() { result += "(deny file-read* file-write* (subpath \"\(path)\"))\n" }
        result += "(deny file-write* (subpath \"\(application.path)\"))\n"
        result += "(deny file-write* (subpath \"\(wrapper)\"))\n"
        let trustedRoot=home.appendingPathComponent("Library/Application Support/HONGAI-CAGE-Desktop")
        for name in ["enrolled-handoff.json","workspace.json","boundary.sb"] {result += "(deny file-write* (literal \"\(trustedRoot.appendingPathComponent(name).path)\"))\n"}
        result += "(deny file-write* (require-all (subpath \"\(trustedRoot.path)\") (require-not (subpath \"\(trustedRoot.appendingPathComponent("profile").path)\")) (require-not (subpath \"\(trustedRoot.appendingPathComponent("temp").path)\")) (require-not (subpath \"\(trustedRoot.appendingPathComponent("tool-home").path)\"))))\n"
        return result
    }
}

func checkStorageBudget(_ root:URL,maximumBytes:Int64=3*1024*1024*1024,maximumEntries:Int=30000) throws {
    let keys:Set<URLResourceKey>=[.isSymbolicLinkKey,.isRegularFileKey,.fileSizeKey]
    var failed=false
    func disappeared(_ error:Error)->Bool {
        let issue=error as NSError
        return issue.domain == NSCocoaErrorDomain && [NSFileNoSuchFileError,NSFileReadNoSuchFileError].contains(issue.code)
    }
    guard let iterator=FileManager.default.enumerator(at:root,includingPropertiesForKeys:Array(keys),options:[],errorHandler:{_,error in if disappeared(error){return true};failed=true;return false}) else {throw CageFailure("隔离存储无法核验，会话已停止。")}
    var entries=0,bytes:Int64=0
    for case let file as URL in iterator {
        entries+=1
        if entries > maximumEntries {throw CageFailure("隔离存储条目超过预算，请先整理本工具的数据。")}
        let values:URLResourceValues
        do {values=try file.resourceValues(forKeys:keys)} catch {if disappeared(error){continue};throw error}
        if values.isSymbolicLink == true {iterator.skipDescendants();continue}
        if values.isRegularFile == true {bytes+=Int64(values.fileSize ?? 0)}
        if bytes > maximumBytes {throw CageFailure("隔离数据超过 3 GB 软容量预算，会话已停止；客户文件未删除。")}
    }
    if failed {throw CageFailure("隔离存储检查未完成，会话已停止。")}
}

func storageSelfTest() throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent("hongai-storage-"+UUID().uuidString)
    try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
    defer {try? FileManager.default.removeItem(at:root)}
    try Data(repeating:0,count:128).write(to:root.appendingPathComponent("fixture"))
    try FileManager.default.createSymbolicLink(at:root.appendingPathComponent("own-cycle"),withDestinationURL:root)
    try checkStorageBudget(root,maximumBytes:256,maximumEntries:5)
    var denied=false
    do {try checkStorageBudget(root,maximumBytes:64,maximumEntries:5)} catch {denied=true}
    guard denied else {throw CageFailure("STORAGE_BYTE_LIMIT_NOT_ENFORCED")}
    denied=false
    do {try checkStorageBudget(root,maximumBytes:256,maximumEntries:1)} catch {denied=true}
    guard denied else {throw CageFailure("STORAGE_ENTRY_LIMIT_NOT_ENFORCED")}
    print("PASS storage budget: bounded traversal, byte limit, entry limit, no symlink traversal")
}

final class CageController: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var window: NSWindow!
    let status = NSTextField(wrappingLabelWithString:"导入第一步交接文件，选择工作文件夹，再启动官方桌面版。")
    let fileLabel = NSTextField(labelWithString:"未选择交接文件")
    let workspaceLabel = NSTextField(labelWithString:"未选择工作文件夹")
    let start = NSButton(title:"启动 Claude 桌面版", target:nil, action:nil)
    var handoffURL: URL?, workspace: URL?, process: Process?, timer: Timer?
    var broker: SessionBroker?
    var busy = false, generation = UUID(), nextStorageCheck:UInt64=0
    var statusItem:NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect:NSRect(x:0,y:0,width:650,height:500), styleMask:[.titled,.closable,.miniaturizable], backing:.buffered, defer:false)
        window.title = "HONG AI CAGE · 桌面进程隔离测试版"; window.center()
        window.delegate=self;window.isReleasedWhenClosed=false
        window.appearance=NSAppearance(named:.aqua)
        window.contentView!.wantsLayer=true
        window.contentView!.layer!.backgroundColor=NSColor(calibratedWhite:0.975,alpha:1).cgColor
        let content = NSStackView(); content.orientation = .vertical; content.alignment = .leading; content.spacing = 18; content.edgeInsets = NSEdgeInsets(top:28,left:30,bottom:28,right:30)
        let brand = NSTextField(labelWithString:"HONG AI  /  CAGE")
        brand.font = .systemFont(ofSize:27,weight:.bold); brand.textColor = NSColor(calibratedRed:0.7,green:0.05,blue:0.12,alpha:1)
        let subtitle = NSTextField(labelWithString:"官方桌面程序 · 指定代理端口 · 独立登录数据")
        subtitle.textColor = .secondaryLabelColor
        let choose = NSButton(title:"① 选择交接文件",target:self,action:#selector(chooseHandoff))
        let folder = NSButton(title:"② 选择工作文件夹",target:self,action:#selector(chooseWorkspace))
        start.target = self; start.action = #selector(startSession); start.bezelStyle = .rounded
        let stop = NSButton(title:"停止隔离会话",target:self,action:#selector(stopSession))
        for button in [choose,folder,start,stop] {button.bezelStyle = .rounded;button.controlSize = .large}
        start.contentTintColor=NSColor(calibratedRed:0.7,green:0.05,blue:0.12,alpha:1)
        let actions = NSStackView(views:[start,stop]); actions.spacing = 18
        let note = NSTextField(wrappingLabelWithString:"保留现有 Clash、Wi-Fi 和远控设置。仅本进程树受限；外部浏览器登录、Cowork 和系统集成尚未验收。")
        note.font = .systemFont(ofSize:12); note.textColor = .secondaryLabelColor
        for view in [brand,subtitle,choose,fileLabel,folder,workspaceLabel,actions,status,note] { content.addArrangedSubview(view) }
        content.translatesAutoresizingMaskIntoConstraints = false; window.contentView!.addSubview(content)
        NSLayoutConstraint.activate([content.leadingAnchor.constraint(equalTo:window.contentView!.leadingAnchor),content.trailingAnchor.constraint(equalTo:window.contentView!.trailingAnchor),content.topAnchor.constraint(equalTo:window.contentView!.topAnchor)])
        let item=NSStatusBar.system.statusItem(withLength:NSStatusItem.variableLength)
        item.button?.title="CAGE";item.button?.toolTip="HONG AI CAGE"
        let menu=NSMenu()
        let settings=NSMenuItem(title:"设置与运行状态",action:#selector(showSettings),keyEquivalent:"");settings.target=self;menu.addItem(settings)
        let end=NSMenuItem(title:"停止隔离会话",action:#selector(stopSession),keyEquivalent:"");end.target=self;menu.addItem(end)
        let quit=NSMenuItem(title:"停止并退出",action:#selector(quitCage),keyEquivalent:"q");quit.target=self;menu.addItem(quit)
        item.menu=menu;statusItem=item
        let trustedRoot=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/HONGAI-CAGE-Desktop")
        let enrolled=trustedRoot.appendingPathComponent("enrolled-handoff.json")
        if FileManager.default.fileExists(atPath:enrolled.path){handoffURL=enrolled;fileLabel.stringValue="已保存交接配置；启动时自动重新核验出口。"}
        if let data=try? Data(contentsOf:trustedRoot.appendingPathComponent("workspace.json")),let object=(try? JSONSerialization.jsonObject(with:data)) as? [String:String],let path=object["workspace"]{workspace=URL(fileURLWithPath:path);workspaceLabel.stringValue=path}
        if CommandLine.arguments.contains("--ui-smoke-test") {
            showSettings()
            DispatchQueue.main.asyncAfter(deadline:.now()+2) {
                guard self.window.isVisible,self.window.contentView!.subviews.count > 0 else {exit(1)}
                if let path=ProcessInfo.processInfo.environment["HONGAI_UI_SNAPSHOT"],let view=self.window.contentView,
                   let bitmap=view.bitmapImageRepForCachingDisplay(in:view.bounds) {
                    view.cacheDisplay(in:view.bounds,to:bitmap)
                    if let data=bitmap.representation(using:.png,properties:[:]) {try? data.write(to:URL(fileURLWithPath:path))}
                }
                print("PASS installed native UI opens without account login or network configuration changes")
                NSApp.terminate(nil)
            }
        } else if !CommandLine.arguments.contains("--settings"),handoffURL != nil,workspace != nil {
            NSApp.setActivationPolicy(.accessory);window.orderOut(nil);startSession()
        } else {
            showSettings()
        }
    }
    @objc func showSettings(){NSApp.setActivationPolicy(.regular);window.makeKeyAndOrderFront(nil);NSApp.activate(ignoringOtherApps:true)}
    @objc func quitCage(){stopSession();NSApp.terminate(nil)}
    func windowShouldClose(_ sender:NSWindow)->Bool {sender.orderOut(nil);NSApp.setActivationPolicy(.accessory);return false}
    func applicationShouldHandleReopen(_ sender:NSApplication,hasVisibleWindows flag:Bool)->Bool {
        if process != nil {NSRunningApplication.runningApplications(withBundleIdentifier:"com.anthropic.claudefordesktop").first?.activate(options:[.activateIgnoringOtherApps])}
        else if !busy,handoffURL != nil,workspace != nil {startSession()}
        else {showSettings()}
        return false
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
                let home=FileManager.default.homeDirectoryForCurrentUser
                let root=home.appendingPathComponent("Library/Application Support/HONGAI-CAGE-Desktop")
                guard !workspace.path.hasPrefix(root.path+"/"),!root.path.hasPrefix(workspace.path+"/"),workspace != root,!home.path.hasPrefix(workspace.path+"/") else {throw CageFailure("请选择独立项目目录，不能选择系统、用户根目录或隔离配置目录。")}
                let enrolled=root.appendingPathComponent("enrolled-handoff.json")
                let admissionData=try Data(contentsOf:file)
                let h=try Handoff.decode(admissionData,requireFresh:file.standardizedFileURL != enrolled.standardizedFileURL), app=try CageRuntime.officialApp()
                for _ in 0..<3 { try CageRuntime.verifyExit(h) }
                guard root.resolvingSymlinksInPath() == root.standardizedFileURL else {throw CageFailure("隔离目录包含链接，请由维护人员检查。")}
                try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
                let ownProfile=root.appendingPathComponent("profile"), temp=root.appendingPathComponent("temp"), toolHome=root.appendingPathComponent("tool-home")
                for item in [ownProfile,temp,toolHome] { try FileManager.default.createDirectory(at:item,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]) }
                let broker=SessionBroker(upstream:UInt16(h.loopback.mixedPort));try broker.start()
                let sessionProxy="http://127.0.0.1:\(broker.port)"
                let policy=root.appendingPathComponent("boundary.sb")
                try CageRuntime.profile(port:Int(broker.port),application:app,home:home).write(to:policy,atomically:true,encoding:.utf8)
                let p=Process(); p.executableURL=Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/CageSession")
                p.arguments=["/usr/bin/sandbox-exec","-f",policy.path,app.appendingPathComponent("Contents/MacOS/Claude").path,"--user-data-dir=\(ownProfile.path)","--proxy-server=\(sessionProxy)","--proxy-bypass-list=<-loopback>","--disable-quic","--disk-cache-size=268435456","--media-cache-size=134217728"]
                p.currentDirectoryURL=workspace
                p.environment=["PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin","HOME":toolHome.path,"TMPDIR":temp.path,"HTTP_PROXY":sessionProxy,"HTTPS_PROXY":sessionProxy,"ALL_PROXY":sessionProxy,"NO_PROXY":"","LANG":"en_US.UTF-8"]
                p.standardOutput=FileHandle.nullDevice; p.standardError=FileHandle.nullDevice
                if CommandLine.arguments.contains("--daily-launch-smoke-test"),ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",ProcessInfo.processInfo.environment["RUNNER_OS"] == "macOS" {
                    let log=temp.appendingPathComponent("official-daily-start.log")
                    FileManager.default.createFile(atPath:log.path,contents:nil)
                    let file=try FileHandle(forWritingTo:log);p.standardOutput=file;p.standardError=file
                }
                DispatchQueue.main.async {
                    do {
                        guard self.generation == token else {broker.stop();return}
                        try p.run(); self.process=p;self.broker=broker;self.busy=false;self.nextStorageCheck=0
                        try admissionData.write(to:enrolled,options:.atomic)
                        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:enrolled.path)
                        try JSONSerialization.data(withJSONObject:["workspace":workspace.path]).write(to:root.appendingPathComponent("workspace.json"),options:.atomic)
                        self.handoffURL=enrolled
                        p.terminationHandler={ _ in DispatchQueue.main.async { if self.process === p { self.stopSession(); self.status.stringValue="桌面进程已退出。" } } }
                        self.status.stringValue="隔离会话运行中；指定出口 \(h.expectedEgressIp)。"
                        self.timer=Timer.scheduledTimer(withTimeInterval:4,repeats:true) { _ in self.verifyRunning(h,token:token) }
                        if CommandLine.arguments.contains("--daily-launch-smoke-test"),ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",ProcessInfo.processInfo.environment["RUNNER_OS"] == "macOS" {
                            DispatchQueue.main.asyncAfter(deadline:.now()+8){
                                guard p.isRunning,!self.window.isVisible else {fputs("DAILY_LAUNCH_DID_NOT_START_OR_REPEATED_SETTINGS running=\(p.isRunning) visible=\(self.window.isVisible) status=\(self.status.stringValue)\n",stderr);exit(1)}
                                print("PASS daily automatic launch uses saved configuration without showing setup")
                                self.stopSession();NSApp.terminate(nil)
                            }
                        }
                    } catch {broker.stop();self.stopSession();self.status.stringValue="启动失败：\(error)";self.showSettings()}
                }
            } catch { DispatchQueue.main.async { self.busy=false; self.start.isEnabled=true; self.status.stringValue="未启动：\(error)";self.showSettings() } }
        }
    }
    func verifyRunning(_ h:Handoff,token:UUID) {
        guard !busy else { return }; busy=true
        DispatchQueue.global(qos:.utility).async {
            do {
                if DispatchTime.now().uptimeNanoseconds >= self.nextStorageCheck {
                    let root=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/HONGAI-CAGE-Desktop")
                    try checkStorageBudget(root)
                    self.nextStorageCheck=DispatchTime.now().uptimeNanoseconds+30_000_000_000
                }
                try CageRuntime.verifyExit(h)
                DispatchQueue.main.async {if self.generation == token {self.broker?.refresh()};self.busy=false}
            }
            catch { DispatchQueue.main.async { if self.generation == token { self.stopSession(); self.status.stringValue="代理不可用或出口变化，会话已停止。" } } }
        }
    }
    @objc func stopSession() {
        generation=UUID(); timer?.invalidate(); timer=nil
        broker?.stop();broker=nil
        if let p=process, p.isRunning {kill(-p.processIdentifier,SIGKILL);kill(p.processIdentifier,SIGKILL)}
        process=nil; busy=false; start.isEnabled=true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication)->Bool {false}
    func applicationWillTerminate(_ notification:Notification) {stopSession()}
}

if CommandLine.arguments.contains("--storage-self-test") {
    do {try storageSelfTest();exit(0)} catch {fputs("\(error)\n",stderr);exit(1)}
}
if CommandLine.arguments.contains("--broker-self-test") {
    do {try brokerSelfTest();exit(0)} catch {fputs("\(error)\n",stderr);exit(1)}
}
if CommandLine.arguments.count == 5 && CommandLine.arguments[1] == "--create-handoff" {
    do {
        guard let port=Int(CommandLine.arguments[2]) else {throw CageFailure("INVALID_PROXY_PORT")}
        let ip=CommandLine.arguments[3],date=ISO8601DateFormatter().string(from:Date())
        let route=SHA256.hash(data:Data("\(port)|\(ip)|\(date)|\(UUID().uuidString)".utf8)).map{String(format:"%02x",$0)}.joined().prefix(24)
        let object:[String:Any] = ["version":1,"tool":"clash","loopback":["protocol":"http","host":"127.0.0.1","mixedPort":port],"expectedEgressIp":ip,"routeId":String(route),"generatedAt":date]
        let data=try JSONSerialization.data(withJSONObject:object,options:[.prettyPrinted,.sortedKeys])
        let handoff=try Handoff.decode(data)
        for _ in 0..<3 {try CageRuntime.verifyExit(handoff)}
        let destination=URL(fileURLWithPath:CommandLine.arguments[4]).standardizedFileURL
        guard destination.lastPathComponent == "clash-handoff.json" else {throw CageFailure("OUTPUT_MUST_BE_CLASH_HANDOFF_JSON")}
        try data.write(to:destination,options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:destination.path)
        print("已核验三次出口并生成交接文件：\(destination.path)")
        exit(0)
    } catch {fputs("\(error)\n",stderr);exit(1)}
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
if CommandLine.arguments.contains("--daily-launch-smoke-test"),ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] != "true" || ProcessInfo.processInfo.environment["RUNNER_OS"] != "macOS" {fputs("DAILY_LAUNCH_SMOKE_REQUIRES_DISPOSABLE_CI\n",stderr);exit(64)}
let application=NSApplication.shared
let delegate=CageController()
application.delegate=delegate
application.setActivationPolicy(.regular)
application.run()
