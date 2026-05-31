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
let policyActions = ["prompt", "allow", "block"]

// ───── shared models ────────────────────────────────────────────────────────

struct Request: Codable {
    let id, exe, human_chain, path, category: String
    let pid: Int
}
struct Reply: Codable { let decision, scope: String }
struct PolicyEntry: Codable { var glob: String; var action: String }
struct PolicyDoc: Codable { var policy: [PolicyEntry] }
struct HistoryRow: Codable { let ts: Int; let verdict, path, process, category: String }
struct RuleRow: Codable { let id: Int; let glob, identity_kind, verdict, created_by: String }

func loadJSON<T: Decodable>(_ path: String, _ type: T.Type) -> T? {
    guard let data = FileManager.default.contents(atPath: path) else { return nil }
    return try? JSONDecoder().decode(T.self, from: data)
}

// ───── dashboard window ─────────────────────────────────────────────────────

final class Dashboard: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    var window: NSWindow!
    let historyTable = NSTableView()
    let rulesTable = NSTableView()
    let policyTable = NSTableView()
    var history: [HistoryRow] = []
    var rules: [RuleRow] = []
    var policy: [PolicyEntry] = []
    var refresh: Timer?

    func show() {
        if window == nil { build() }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        reload(reloadPolicy: true)
        refresh = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            self?.reload(reloadPolicy: false) // don't clobber in-progress edits
        }
    }
    func windowWillClose(_ n: Notification) { refresh?.invalidate(); refresh = nil }

    func build() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 740, height: 460),
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

    func col(_ id: String, _ title: String, _ w: CGFloat) -> NSTableColumn {
        let c = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id))
        c.title = title; c.width = w
        return c
    }
    func scrolling(_ v: NSView, _ frame: NSRect) -> NSScrollView {
        let s = NSScrollView(frame: frame)
        s.hasVerticalScroller = true; s.documentView = v
        s.autoresizingMask = [.width, .height]
        return s
    }
    func tab(_ label: String, _ build: (NSView) -> Void) -> NSTabViewItem {
        let item = NSTabViewItem(); item.label = label
        let v = NSView(frame: NSRect(x: 0, y: 0, width: 740, height: 430))
        build(v); item.view = v
        return item
    }

    func historyTab() -> NSTabViewItem {
        historyTable.addTableColumn(col("time", "Time", 130))
        historyTable.addTableColumn(col("verdict", "Verdict", 70))
        historyTable.addTableColumn(col("path", "File", 340))
        historyTable.addTableColumn(col("process", "Process", 160))
        historyTable.dataSource = self; historyTable.delegate = self
        historyTable.usesAlternatingRowBackgroundColors = true
        return tab("History") { $0.addSubview(scrolling(historyTable, $0.bounds)) }
    }

    func policyTab() -> NSTabViewItem {
        policyTable.addTableColumn(col("glob", "File / glob", 470))
        policyTable.addTableColumn(col("action", "Action", 130))
        policyTable.dataSource = self; policyTable.delegate = self
        policyTable.usesAlternatingRowBackgroundColors = true
        return tab("Policy") { v in
            v.addSubview(scrolling(policyTable, NSRect(x: 0, y: 44, width: 740, height: 386)))
            let add = NSButton(title: "Add", target: self, action: #selector(addPolicy))
            add.frame = NSRect(x: 10, y: 8, width: 70, height: 28)
            let rem = NSButton(title: "Remove", target: self, action: #selector(removePolicy))
            rem.frame = NSRect(x: 86, y: 8, width: 80, height: 28)
            let save = NSButton(title: "Save", target: self, action: #selector(savePolicy))
            save.bezelStyle = .rounded; save.keyEquivalent = "\r"
            save.frame = NSRect(x: 740 - 90, y: 8, width: 80, height: 28)
            save.autoresizingMask = [.minXMargin]
            v.addSubview(add); v.addSubview(rem); v.addSubview(save)
        }
    }

    func rulesTab() -> NSTabViewItem {
        rulesTable.addTableColumn(col("glob", "Glob", 230))
        rulesTable.addTableColumn(col("kind", "Match", 90))
        rulesTable.addTableColumn(col("verdict", "Verdict", 70))
        rulesTable.addTableColumn(col("by", "By", 90))
        rulesTable.dataSource = self; rulesTable.delegate = self
        rulesTable.usesAlternatingRowBackgroundColors = true
        return tab("Rules") { v in
            v.addSubview(scrolling(rulesTable, NSRect(x: 0, y: 44, width: 740, height: 386)))
            let revoke = NSButton(title: "Revoke Selected", target: self, action: #selector(revokeSelected))
            revoke.bezelStyle = .rounded
            revoke.frame = NSRect(x: 740 - 160, y: 8, width: 150, height: 28)
            revoke.autoresizingMask = [.minXMargin]
            v.addSubview(revoke)
        }
    }

    func reload(reloadPolicy: Bool) {
        history = loadJSON(historyPath, [HistoryRow].self) ?? []
        rules = loadJSON(rulesPath, [RuleRow].self) ?? []
        historyTable.reloadData(); rulesTable.reloadData()
        if reloadPolicy, let doc = loadJSON(policyPath, PolicyDoc.self) {
            policy = doc.policy
            policyTable.reloadData()
        }
    }

    // NSTableViewDataSource
    func numberOfRows(in t: NSTableView) -> Int {
        switch t {
        case historyTable: return history.count
        case rulesTable: return rules.count
        default: return policy.count
        }
    }

    // NSTableViewDelegate — view-based cells.
    func tableView(_ t: NSTableView, viewFor col: NSTableColumn?, row: Int) -> NSView? {
        let id = col?.identifier.rawValue ?? ""
        if t === policyTable {
            if id == "glob" {
                let f = NSTextField(string: policy[row].glob)
                f.isEditable = true; f.isBordered = false; f.backgroundColor = .clear
                f.target = self; f.action = #selector(globEdited(_:))
                f.cell?.sendsActionOnEndEditing = true
                return f
            }
            let p = NSPopUpButton(frame: .zero, pullsDown: false)
            p.addItems(withTitles: policyActions)
            p.selectItem(withTitle: policy[row].action)
            p.target = self; p.action = #selector(actionChanged(_:))
            return p
        }
        return Self.label(text(for: t, id: id, row: row))
    }

    func text(for t: NSTableView, id: String, row: Int) -> String {
        if t === historyTable {
            let h = history[row]
            switch id {
            case "time": return Self.fmt(h.ts)
            case "verdict": return h.verdict
            case "path": return h.path
            default: return h.process
            }
        }
        let r = rules[row]
        switch id {
        case "glob": return r.glob
        case "kind": return r.identity_kind
        case "verdict": return r.verdict
        default: return r.created_by
        }
    }

    static func label(_ s: String) -> NSTextField {
        let f = NSTextField(labelWithString: s)
        f.lineBreakMode = .byTruncatingMiddle
        return f
    }

    // Policy editing
    @objc func globEdited(_ sender: NSTextField) {
        let r = policyTable.row(for: sender)
        if r >= 0 && r < policy.count { policy[r].glob = sender.stringValue }
    }
    @objc func actionChanged(_ sender: NSPopUpButton) {
        let r = policyTable.row(for: sender)
        if r >= 0 && r < policy.count { policy[r].action = sender.titleOfSelectedItem ?? "prompt" }
    }
    @objc func addPolicy() {
        policy.append(PolicyEntry(glob: "", action: "prompt"))
        policyTable.reloadData()
        policyTable.editColumn(0, row: policy.count - 1, with: nil, select: true)
    }
    @objc func removePolicy() {
        let r = policyTable.selectedRow
        guard r >= 0 && r < policy.count else { return }
        policy.remove(at: r); policyTable.reloadData()
    }
    @objc func savePolicy() {
        let entries = policy.filter { !$0.glob.trimmingCharacters(in: .whitespaces).isEmpty }
        if let data = try? JSONEncoder().encode(PolicyDoc(policy: entries)) {
            try? data.write(to: URL(fileURLWithPath: policyPath))
        }
    }

    @objc func revokeSelected() {
        let r = rulesTable.selectedRow
        guard r >= 0 && r < rules.count else { return }
        try? FileManager.default.createDirectory(atPath: commandsDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: "\(commandsDir)/revoke-\(rules[r].id).cmd", contents: Data())
    }

    static let df: DateFormatter = { let f = DateFormatter(); f.dateFormat = "MM-dd HH:mm:ss"; return f }()
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
        // White (template) shield that adapts to the menu bar, not a color emoji.
        if let img = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "scdlp") {
            img.isTemplate = true
            statusItem.button?.image = img
        } else {
            statusItem.button?.title = "scdlp"
        }
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
        busy = true; defer { busy = false }
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
        scope.addItems(withTitles: ["Just this once", "Always — for \(exe) (any launch)", "Always — for this exact process"])
        scope.selectItem(at: 1)
        alert.accessoryView = scope
        NSApp.activate(ignoringOtherApps: true)
        let resp = alert.runModal()
        let decision = (resp == .alertSecondButtonReturn) ? "allow" : "deny"
        let scopeStr = ["once", "always-exe", "always"][min(max(scope.indexOfSelectedItem, 0), 2)]
        if let data = try? JSONEncoder().encode(Reply(decision: decision, scope: scopeStr)) {
            try? data.write(to: URL(fileURLWithPath: replyPath))
        }
        decisions += 1; rebuildMenu()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
