import Foundation
import CryptoKit

enum OfficialRuntime {
    static let requirement = "anchor apple generic and identifier \"com.anthropic.claudefordesktop\" and certificate leaf[subject.OU] = \"Q6L2SF6YDW\""
    static func version(_ app:URL) throws -> String {
        let data=try Data(contentsOf:app.appendingPathComponent("Contents/Info.plist"))
        guard let info=try PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any],
              info["CFBundleIdentifier"] as? String == "com.anthropic.claudefordesktop",
              let version=info["CFBundleVersion"] as? String,
              version.range(of:"^[0-9]+(?:\\.[0-9]+)*$",options:.regularExpression) != nil else {throw CageFailure("官方应用标识或版本无法核验。")}
        if let minimum=info["LSMinimumSystemVersion"] as? String {
            let current=ProcessInfo.processInfo.operatingSystemVersion
            let os="\(current.majorVersion).\(current.minorVersion).\(current.patchVersion)"
            guard os.compare(minimum,options:.numeric) != .orderedAscending else {throw CageFailure("此 Claude 版本要求 macOS \(minimum) 或更新版本。")}
        }
        return version
    }
    static func verify(_ app:URL) throws {
        _=try version(app)
        _=try CageRuntime.command("/usr/bin/codesign",["--verify","--deep","--strict","-R="+requirement,app.path],timeout:60)
    }
    static func snapshot(_ source:URL,root:URL) throws -> URL {
        let fm=FileManager.default
        try verify(source)
        let info=try Data(contentsOf:source.appendingPathComponent("Contents/Info.plist"))
        let identity="v"+(try version(source))+"-"+SHA256.hash(data:info).prefix(8).map{String(format:"%02x",$0)}.joined()
        let cache=root.appendingPathComponent("official-runtime")
        try fm.createDirectory(at:cache,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        guard cache.resolvingSymlinksInPath() == cache.standardizedFileURL else {throw CageFailure("运行缓存包含链接，已停止。")}
        let target=cache.appendingPathComponent(identity),app=target.appendingPathComponent("Claude.app")
        // Keep the selected version and its immediately previous complete copy.
        // Other data and original applications are never cleanup targets.
        let entries=try fm.contentsOfDirectory(at:cache,includingPropertiesForKeys:nil).filter{$0.lastPathComponent.range(of:"^v[0-9.]+-[a-f0-9]{16}$",options:.regularExpression) != nil}
        let other=entries.filter{$0 != target}.sorted{$0.lastPathComponent.compare($1.lastPathComponent,options:.numeric) == .orderedDescending}
        for old in other.dropFirst() {
            guard old.deletingLastPathComponent() == cache,old.resolvingSymlinksInPath() == old.standardizedFileURL,
                  let marker=try? Data(contentsOf:old.appendingPathComponent("owner.json")),
                  let record=(try? JSONSerialization.jsonObject(with:marker)) as? [String:String],record["schema"] == "hongai.official-mac-runtime.v1",record["identity"] == old.lastPathComponent else {throw CageFailure("旧运行缓存归属无法核验，未删除。")}
            try verify(old.appendingPathComponent("Claude.app"))
            try fm.removeItem(at:old)
        }
        if fm.fileExists(atPath:app.path) {
            guard target.resolvingSymlinksInPath() == target.standardizedFileURL else {throw CageFailure("运行版本目录包含链接。")}
            try verify(app)
            guard try Data(contentsOf:app.appendingPathComponent("Contents/Info.plist")) == info else {throw CageFailure("缓存版本与官方来源不一致。")}
            return app
        }
        let stage=cache.appendingPathComponent(".stage-"+UUID().uuidString)
        try fm.createDirectory(at:stage,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        do {
            _=try CageRuntime.command("/usr/bin/ditto",[source.path,stage.appendingPathComponent("Claude.app").path],timeout:120)
            try verify(stage.appendingPathComponent("Claude.app"))
            guard try Data(contentsOf:source.appendingPathComponent("Contents/Info.plist")) == info else {throw CageFailure("复制期间官方版本变化，请重试。")}
            try JSONSerialization.data(withJSONObject:["schema":"hongai.official-mac-runtime.v1","identity":identity,"version":try version(source)]).write(to:stage.appendingPathComponent("owner.json"),options:.atomic)
            try fm.moveItem(at:stage,to:target)
        } catch {
            // Stage is a newly created, exact owned child. Keep the original
            // and last complete runtime intact on interruption/failure.
            if stage.deletingLastPathComponent() == cache,stage.resolvingSymlinksInPath() == stage.standardizedFileURL {try? fm.removeItem(at:stage)}
            throw error
        }
        return app
    }
    static func installLatest(root:URL,proxy:String?) throws -> String {
        let fm=FileManager.default
        let download=root.appendingPathComponent("official-download")
        try fm.createDirectory(at:download,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        guard download.resolvingSymlinksInPath() == download.standardizedFileURL else {throw CageFailure("下载目录包含链接。")}
        var common=["--silent","--show-error","--fail","--max-time","180","--proto","=https","--max-filesize","1200000000"]
        if let proxy=proxy {common += ["--noproxy","","--proxy",proxy]}
        let manifest=try CageRuntime.command("/usr/bin/curl",common+["https://downloads.claude.ai/releases/darwin/universal/RELEASES.json"],timeout:190)
        guard let object=(try? JSONSerialization.jsonObject(with:Data(manifest.utf8))) as? [String:Any],let latest=object["currentRelease"] as? String,
              latest.range(of:"^[0-9]+(?:\\.[0-9]+)*$",options:.regularExpression) != nil,
              let releases=object["releases"] as? [[String:Any]],let release=releases.first(where:{$0["version"] as? String == latest}),
              let update=release["updateTo"] as? [String:Any],let address=update["url"] as? String,
              let url=URL(string:address),url.scheme == "https",url.host == "downloads.claude.ai",url.user == nil,url.password == nil,
              url.path.hasPrefix("/releases/darwin/universal/\(latest)/Claude-"),url.path.hasSuffix(".zip"),url.query == nil else {throw CageFailure("官方更新清单格式不支持，保留现有版本。")}
        let source=try? CageRuntime.officialApp()
        if let source=source,(try version(source)).compare(latest,options:.numeric) != .orderedAscending {return "官方 Claude 已是 \(try version(source))，无需更新。"}
        let stage=download.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at:stage,withIntermediateDirectories:false)
        defer {if stage.deletingLastPathComponent() == download,stage.resolvingSymlinksInPath() == stage.standardizedFileURL {try? fm.removeItem(at:stage)}}
        let archive=stage.appendingPathComponent("Claude.zip"),expanded=stage.appendingPathComponent("expanded")
        _=try CageRuntime.command("/usr/bin/curl",common+["--output",archive.path,address],timeout:190)
        _=try CageRuntime.command("/usr/bin/ditto",["-x","-k",archive.path,expanded.path],timeout:120)
        let candidate=expanded.appendingPathComponent("Claude.app")
        try verify(candidate)
        guard try version(candidate) == latest else {throw CageFailure("官方清单与下载版本不一致。")}
        // Install into the customer's own Applications folder. No root helper,
        // login daemon, network extension or change to /Applications is needed.
        let applications=fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications")
        try fm.createDirectory(at:applications,withIntermediateDirectories:true)
        guard applications.resolvingSymlinksInPath() == applications.standardizedFileURL else {throw CageFailure("用户应用目录包含链接。")}
        let target=applications.appendingPathComponent("Claude.app"),pending=applications.appendingPathComponent(".HONGAI-Claude-"+UUID().uuidString+".app")
        _=try CageRuntime.command("/usr/bin/ditto",[candidate.path,pending.path],timeout:120)
        try verify(pending)
        var backup:URL?
        if fm.fileExists(atPath:target.path) {
            try verify(target)
            let recovery=root.appendingPathComponent("Recovery")
            try fm.createDirectory(at:recovery,withIntermediateDirectories:true)
            guard recovery.resolvingSymlinksInPath() == recovery.standardizedFileURL else {throw CageFailure("恢复目录包含链接。")}
            let old=recovery.appendingPathComponent("Claude-"+UUID().uuidString+".app")
            try fm.moveItem(at:target,to:old);backup=old
        }
        do {try fm.moveItem(at:pending,to:target)} catch {if let old=backup,!fm.fileExists(atPath:target.path){try? fm.moveItem(at:old,to:target)};throw error}
        return "官方 Claude \(latest) 已就绪；下次启动继续使用相同出口和隔离规则。"
    }
}
