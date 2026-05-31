// scdlp-helper — the user-session menu bar app: approval prompts + a dashboard
// (History / Policy / Rules). It talks to the root extension purely through the
// shared spool + control directory (no XPC yet).
import Cocoa
import Foundation

let stateDir = "/Library/Application Support/scdlp"
let spoolDir = "\(stateDir)/prompts"
let heartbeatPath = "\(spoolDir)/.helper-alive"
let controlDir = "\(stateDir)/control"
let policyPath = "\(controlDir)/policy.json"
let historyPath = "\(controlDir)/history.json"
let rulesPath = "\(controlDir)/rules.json"
let commandsDir = "\(controlDir)/commands"

// ───── shared models ────────────────────────────────────────────────────────

struct Request: Codable {
    let id: String
    let pid: Int
    let exe: String
    let human_chain: String
    let path: String
    let category: String
}
struct Reply: Codable {
    let decision: String // "allow" | "deny"
    let scope: String    // "once" | "always" | "always-exe"
}
struct PolicyEntry: Codable {
    let glob: String
    let action: String
}
struct PolicyDoc: Codable { var policy: [PolicyEntry] }
struct HistoryRow: Codable {
    let ts: Int
    let verdict: String
    let path: String
    let process: String
    let category: String
}
struct RuleRow: Codable {
    let id: Int
    let glob: String
    let identity_kind: String
    let verdict: String
    let created_by: String
}

func loadJSON<T: Decodable>(_ path: String, _ type: T.Type) -> T? {
    guard let data = FileManager.default.contents(atPath: path) else { return nil }
    return try? JSONDecoder().decode(T.self, from: data)
}

// ───── dashboard window ─────────────────────────────────────────────────────

final class Dashboard: NSObject, NSWindowDelegate, NSTableViewDataSource {
    var window: NSWindow!
    let historyTable = NSTableView()
    let rulesTable = NSTableView()
    let policyView = NSTextView()
    var history: [HistoryRow] = []
    var rules: [RuleRow] = []
    var refresh: Timer?

    func show() {
        if window == nil { build() }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        reload()
        refresh = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.reload() }
    }

    func windowWillClose(_ n: Notification) { refresh?.invalidate(); refresh = nil }

    func build() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 460),
                          styleMask: [.titled, .closable, .resizable, .miniaturizable],
                          backing: .buffered, defer: false)
        window.title = "scdlp"
        window.delegate = self
        window.center()

        let tabs = NSTabView(frame: window.contentView!.bounds)
        tabs.autoresizingMask = [.width, .height]
        tabs.addTabViewItem(historyTab())
        tabs.addTabViewItem(policyTab())
        tabs.addTabViewItem(rulesTab())
        window.contentView!.addSubview(tabs)
    }

    func column(_ id: String, _ title: String, _ w: CGFloat) -> NSTableColumn {
        let c = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id))
        c.title = title
        c.width = w
        return c
    }

    func scrolling(_ v: NSView) -> NSScrollView {
        let s = NSScrollView()
        s.hasVerticalScroller = true
        s.documentView = v
        s.autoresizingMask = [.width, .height]
        return s
    }

    // History tab — read-only table.
    func historyTab() -> NSTabViewItem {
        historyTable.addTableColumn(column("time", "Time", 140))
        historyTable.addTableColumn(column("verdict", "Verdict", 70))
        historyTable.addTableColumn(column("path", "File", 320))
        historyTable.addTableColumn(column("process", "Process", 160))
        historyTable.dataSource = self
        historyTable.usesAlternatingRowBackgroundColors = true
        let item = NSTabViewItem(); item.label = "History"
        let v = NSView(frame: NSRect(x: 0, y: 0, width: 720, height: 430))
        let sc = scrolling(historyTable); sc.frame = v.bounds
        v.addSubview(sc); item.view = v
        return item
    }

    // Policy tab — editable text (one "action glob" per line) + Save.
    func policyTab() -> NSTabViewItem {
        let item = NSTabViewItem(); item.label = "Policy"
        let v = NSView(frame: NSRect(x: 0, y: 0, width: 720, height: 430))

        let save = NSButton(title: "Save", target: self, action: #selector(savePolicy))
        save.bezelStyle = .rounded
        save.frame = NSRect(x: 720 - 90, y: 8, width: 80, height: 28)
        save.autoresizingMask = [.minXMargin]

        let label = NSTextField(labelWithString: "One rule per line:  <prompt|allow|block>  <glob>")
        label.frame = NSRect(x: 10, y: 10, width: 520, height: 22)
        label.textColor = .secondaryLabelColor

        let sc = scrolling(policyView)
        sc.frame = NSRect(x: 0, y: 44, width: 720, height: 386)
        policyView.isRichText = false
        policyView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        policyView.isVerticallyResizable = true
        policyView.textContainer?.widthTracksTextView = true

        v.addSubview(sc); v.addSubview(label); v.addSubview(save)
        item.view = v
        return item
    }

    // Rules tab — table + Revoke.
    func rulesTab() -> NSTabViewItem {
        rulesTable.addTableColumn(column("glob", "Glob", 220))
        rulesTable.addTableColumn(column("kind", "Match", 90))
        rulesTable.addTableColumn(column("verdict", "Verdict", 70))
        rulesTable.addTableColumn(column("by", "By", 90))
        rulesTable.dataSource = self
        rulesTable.usesAlternatingRowBackgroundColors = true
        let item = NSTabViewItem(); item.label = "Rules"
        let v = NSView(frame: NSRect(x: 0, y: 0, width: 720, height: 430))
        let revoke = NSButton(title: "Revoke Selected", target: self, action: #selector(revokeSelected))
        revoke.bezelStyle = .rounded
        revoke.frame = NSRect(x: 720 - 160, y: 8, width: 150, height: 28)
        revoke.autoresizingMask = [.minXMargin]
        let sc = scrolling(rulesTable)
        sc.frame = NSRect(x: 0, y: 44, width: 720, height: 386)
        v.addSubview(sc); v.addSubview(revoke)
        item.view = v
        return item
    }

    func reload() {
        history = loadJSON(historyPath, [HistoryRow].self) ?? []
        rules = loadJSON(rulesPath, [RuleRow].self) ?? []
        historyTable.reloadData()
        rulesTable.reloadData()
        // Load policy text only when the editor isn't focused (don't clobber edits).
        if window.firstResponder !== policyView, let doc = loadJSON(policyPath, PolicyDoc.self) {
            policyView.string = doc.policy.map { "\($0.action) \($0.glob)" }.joined(separator: "\n")
        }
    }

    @objc func savePolicy() {
        var entries: [PolicyEntry] = []
        for raw in policyView.string.split(separator: "\n") {
            let parts = raw.split(separator: " ", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, !parts[1].isEmpty else { continue }
            let action = ["prompt", "allow", "block"].contains(parts[0]) ? parts[0] : "prompt"
            entries.append(PolicyEntry(glob: parts[1], action: action))
        }
        if let data = try? JSONEncoder().encode(PolicyDoc(policy: entries)) {
            try? data.write(to: URL(fileURLWithPath: policyPath))
        }
    }

    @objc func revokeSelected() {
        let row = rulesTable.selectedRow
        guard row >= 0 && row < rules.count else { return }
        let id = rules[row].id
        try? FileManager.default.createDirectory(atPath: commandsDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: "\(commandsDir)/revoke-\(id).cmd", contents: Data())
    }

    // NSTableViewDataSource (cell-based).
    func numberOfRows(in t: NSTableView) -> Int { t === historyTable ? history.count : rules.count }

    func tableView(_ t: NSTableView, objectValueFor col: NSTableColumn?, row: Int) -> Any? {
        let id = col?.identifier.rawValue ?? ""
        if t === historyTable {
            let h = history[row]
            switch id {
            case "time": return Self.fmt(h.ts)
            case "verdict": return h.verdict
            case "path": return h.path
            case "process": return h.process
            default: return ""
            }
        }
        let r = rules[row]
        switch id {
        case "glob": return r.glob
        case "kind": return r.identity_kind
        case "verdict": return r.verdict
        case "by": return r.created_by
        default: return ""
        }
    }

    static let df: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "MM-dd HH:mm:ss"; return f
    }()
    static func fmt(_ ts: Int) -> String { df.string(from: Date(timeIntervalSince1970: TimeInterval(ts))) }
}

// ───── menu bar app + prompt handling ───────────────────────────────────────

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    let workQ = DispatchQueue(label: "io.sentra.scdlp.helper.work")
    var heartbeatTimer: DispatchSourceTimer?
    var pollTimer: DispatchSourceTimer?
    var busy = false
    var decisions = 0
    let dashboard = Dashboard()
    let staleAfter: TimeInterval = 30

    func applicationDidFinishLaunching(_ note: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🛡"
        rebuildMenu()

        let hb = DispatchSource.makeTimerSource(queue: workQ)
        hb.schedule(deadline: .now(), repeating: 2.0)
        hb.setEventHandler { [weak self] in self?.touchHeartbeat() }
        hb.resume(); heartbeatTimer = hb

        let pt = DispatchSource.makeTimerSource(queue: workQ)
        pt.schedule(deadline: .now() + 0.3, repeating: 0.3)
        pt.setEventHandler { self.scan() }
        pt.resume(); pollTimer = pt
    }

    func touchHeartbeat() { _ = FileManager.default.createFile(atPath: heartbeatPath, contents: Data()) }

    func rebuildMenu() {
        let m = NSMenu()
        m.addItem(withTitle: "scdlp — watching", action: nil, keyEquivalent: "")
        m.addItem(withTitle: "Approvals handled: \(decisions)", action: nil, keyEquivalent: "")
        m.addItem(.separator())
        m.addItem(withTitle: "Open scdlp…", action: #selector(openDashboard), keyEquivalent: "o").target = self
        m.addItem(.separator())
        m.addItem(withTitle: "Quit scdlp-helper", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        statusItem.menu = m
    }

    @objc func openDashboard() { dashboard.show() }

    func scan() {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: spoolDir) else { return }
        for name in names.sorted() where name.hasSuffix(".req.json") {
            let id = String(name.dropLast(".req.json".count))
            let reqPath = "\(spoolDir)/\(name)"
            let replyPath = "\(spoolDir)/\(id).reply.json"
            if fm.fileExists(atPath: replyPath) { continue }
            if let attrs = try? fm.attributesOfItem(atPath: reqPath),
               let mtime = attrs[.modificationDate] as? Date,
               Date().timeIntervalSince(mtime) > staleAfter {
                try? fm.removeItem(atPath: reqPath); continue
            }
            guard let data = fm.contents(atPath: reqPath),
                  let req = try? JSONDecoder().decode(Request.self, from: data) else { continue }
            DispatchQueue.main.async { self.present(req, replyPath: replyPath) }
        }
    }

    func present(_ req: Request, replyPath: String) {
        if busy || FileManager.default.fileExists(atPath: replyPath) { return }
        busy = true
        defer { busy = false }

        let exe = (req.exe as NSString).lastPathComponent
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Allow \(exe) to read a secret file?"
        alert.informativeText = """
        File: \(req.path)
        Category: \(req.category)
        Process: \(req.human_chain.isEmpty ? req.exe : req.human_chain) (pid \(req.pid))
        """
        alert.addButton(withTitle: "Deny")
        alert.addButton(withTitle: "Allow")
        let scope = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 340, height: 25), pullsDown: false)
        scope.addItems(withTitles: ["Just this once",
                                    "Always — for \(exe) (any launch)",
                                    "Always — for this exact process"])
        scope.selectItem(at: 1)
        alert.accessoryView = scope

        NSApp.activate(ignoringOtherApps: true)
        let resp = alert.runModal()
        let decision = (resp == .alertSecondButtonReturn) ? "allow" : "deny"
        let scopeStr: String
        switch scope.indexOfSelectedItem {
        case 0: scopeStr = "once"
        case 2: scopeStr = "always"
        default: scopeStr = "always-exe"
        }
        if let data = try? JSONEncoder().encode(Reply(decision: decision, scope: scopeStr)) {
            try? data.write(to: URL(fileURLWithPath: replyPath))
        }
        decisions += 1
        rebuildMenu()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
