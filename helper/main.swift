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
let disabledMarker = "\(controlDir)/disabled"
let policyActions = ["prompt", "allow", "block"]

// ───── shared models ────────────────────────────────────────────────────────

struct Request: Codable {
    let id, exe, human_chain, path, category: String
    let pid: Int
}
struct Reply: Codable { let decision, scope: String }
struct PolicyEntry: Codable { var glob: String; var action: String }
struct PolicyDoc: Codable { var policy: [PolicyEntry]; var trusted_apps: [String]? }
struct HistoryRow: Codable { let ts: Int; let verdict, path, process, category: String }
struct RuleRow: Codable { let id: Int; let glob, identity_kind, verdict, created_by: String }

func loadJSON<T: Decodable>(_ path: String, _ type: T.Type) -> T? {
    guard let data = FileManager.default.contents(atPath: path) else { return nil }
    return try? JSONDecoder().decode(T.self, from: data)
}

func writePolicyDoc(_ doc: PolicyDoc) {
    let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? enc.encode(doc) { try? data.write(to: URL(fileURLWithPath: policyPath)) }
}

// addTrustedApp appends an app name to policy.json's trusted_apps (the extension
// then allows that app's whole process tree without prompting). Preserves the
// existing policy globs.
func addTrustedApp(_ app: String) {
    let name = app.trimmingCharacters(in: .whitespaces)
    guard !name.isEmpty else { return }
    var doc = loadJSON(policyPath, PolicyDoc.self) ?? PolicyDoc(policy: [], trusted_apps: [])
    var apps = doc.trusted_apps ?? []
    if !apps.contains(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) { apps.append(name) }
    doc.trusted_apps = apps
    writePolicyDoc(doc)
}

// responsibleApp picks the outermost GUI app in a "leaf ← … ← launchd" chain —
// the thing worth trusting (e.g. "Moltty"), not the transient leaf process.
func responsibleApp(fromChain chain: String) -> String {
    chain.components(separatedBy: " ← ")
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty && $0.lowercased() != "launchd" }
        .last ?? ""
}

let aboutText = """
Supply Chain DLP (SCDLP) is a macOS Endpoint Security system extension that \
watches for processes reading credential and secret files — .env files, cloud \
provider credentials (AWS, GCP, Azure), SSH/GPG keys, package-manager and \
git tokens, kubeconfigs, and more.

When an unrecognized process tries to read a protected file, SCDLP blocks the \
read and asks you to approve or deny it — so a compromised dependency, build \
script, or AI agent in your supply chain can't quietly exfiltrate your secrets. \
Your decisions are remembered as scoped rules.

Use the Policy tab to choose which files are protected, Trusted Apps to \
allowlist tools you trust to read secrets, and History to see every decision. \
The menu-bar shield toggles enforcement on and off.
"""

// ───── dashboard window ─────────────────────────────────────────────────────

final class Dashboard: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    var window: NSWindow!
    let historyTable = NSTableView()
    let rulesTable = NSTableView()
    let policyTable = NSTableView()
    var history: [HistoryRow] = []
    var rules: [RuleRow] = []
    var policy: [PolicyEntry] = []
    var trusted: [String] = []
    // GCD timer (not a run-loop NSTimer, which doesn't fire reliably in a
    // LaunchAgent-launched app) so History/Rules update live while open.
    var refresh: DispatchSourceTimer?

    func show() {
        if window == nil { build() }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        reload(reloadPolicy: true)
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "io.sentra.scdlp.helper.ui"))
        t.schedule(deadline: .now() + 2, repeating: 2)
        t.setEventHandler { [weak self] in
            DispatchQueue.main.async { self?.reload(reloadPolicy: false) } // UI on main; keep edits
        }
        t.resume()
        refresh = t
    }
    func windowWillClose(_ n: Notification) { refresh?.cancel(); refresh = nil }
    func windowDidBecomeKey(_ n: Notification) { reload(reloadPolicy: false) }

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
        tabs.addTabViewItem(trustedTab())
        tabs.addTabViewItem(rulesTab())
        tabs.addTabViewItem(aboutTab())
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
            trusted = doc.trusted_apps ?? []
            trustedTable.reloadData()
        }
    }

    // NSTableViewDataSource
    func numberOfRows(in t: NSTableView) -> Int {
        switch t {
        case historyTable: return history.count
        case rulesTable: return rules.count
        case trustedTable: return trusted.count
        default: return policy.count
        }
    }

    // NSTableViewDelegate — view-based cells.
    func tableView(_ t: NSTableView, viewFor col: NSTableColumn?, row: Int) -> NSView? {
        let id = col?.identifier.rawValue ?? ""
        if t === trustedTable { return Self.label(trusted[row]) }
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
        let existing = loadJSON(policyPath, PolicyDoc.self)
        writePolicyDoc(PolicyDoc(policy: entries, trusted_apps: existing?.trusted_apps))
    }

    // ── Trusted Apps tab: a list of allowlisted apps; add via Browse… ──
    let trustedTable = NSTableView()
    func trustedTab() -> NSTabViewItem {
        trustedTable.addTableColumn(col("app", "Trusted application", 700))
        trustedTable.dataSource = self; trustedTable.delegate = self
        trustedTable.usesAlternatingRowBackgroundColors = true
        trustedTable.headerView = nil
        return tab("Trusted Apps") { v in
            let hint = NSTextField(wrappingLabelWithString:
                "Apps listed here may read any protected file without prompting — matched against the whole process tree. Use Browse… to add one.")
            hint.frame = NSRect(x: 12, y: 392, width: 716, height: 32)
            hint.textColor = .secondaryLabelColor
            v.addSubview(hint)
            v.addSubview(scrolling(trustedTable, NSRect(x: 12, y: 48, width: 716, height: 336)))
            let browse = NSButton(title: "Browse…", target: self, action: #selector(browseTrusted))
            browse.bezelStyle = .rounded
            browse.frame = NSRect(x: 12, y: 8, width: 100, height: 28)
            let rem = NSButton(title: "Remove", target: self, action: #selector(removeTrusted))
            rem.frame = NSRect(x: 118, y: 8, width: 90, height: 28)
            v.addSubview(browse); v.addSubview(rem)
        }
    }

    @objc func browseTrusted() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.treatsFilePackagesAsDirectories = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.message = "Choose an application to trust"
        panel.prompt = "Trust"
        if #available(macOS 11, *) { panel.allowedContentTypes = [.application] }
        guard panel.runModal() == .OK else { return }
        // App name = bundle name without ".app" (matches the extension's chain test).
        for url in panel.urls {
            let name = url.deletingPathExtension().lastPathComponent
            if !name.isEmpty, !trusted.contains(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) {
                trusted.append(name)
            }
        }
        persistTrusted()
        trustedTable.reloadData()
    }

    @objc func removeTrusted() {
        let r = trustedTable.selectedRow
        guard r >= 0 && r < trusted.count else { return }
        trusted.remove(at: r)
        persistTrusted()
        trustedTable.reloadData()
    }

    func persistTrusted() {
        let existing = loadJSON(policyPath, PolicyDoc.self)
        writePolicyDoc(PolicyDoc(policy: existing?.policy ?? [], trusted_apps: trusted.isEmpty ? nil : trusted))
    }

    // ── About tab: branding + what SCDLP is ──
    func aboutTab() -> NSTabViewItem {
        return tab("About") { v in
            let icon = NSImageView(frame: NSRect(x: 28, y: 312, width: 88, height: 88))
            let cfg = NSImage.SymbolConfiguration(pointSize: 80, weight: .semibold)
                .applying(NSImage.SymbolConfiguration(paletteColors: [.systemBlue]))
            icon.image = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "SCDLP")?
                .withSymbolConfiguration(cfg)
            v.addSubview(icon)
            let title = NSTextField(labelWithString: "Supply Chain DLP")
            title.font = .systemFont(ofSize: 24, weight: .bold)
            title.frame = NSRect(x: 130, y: 360, width: 580, height: 32)
            v.addSubview(title)
            let sub = NSTextField(labelWithString: "SCDLP · macOS Endpoint Security extension")
            sub.textColor = .secondaryLabelColor
            sub.frame = NSRect(x: 130, y: 332, width: 580, height: 22)
            v.addSubview(sub)
            let body = NSTextField(wrappingLabelWithString: aboutText)
            body.frame = NSRect(x: 28, y: 24, width: 684, height: 280)
            v.addSubview(body)
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

    func isDisabled() -> Bool { FileManager.default.fileExists(atPath: disabledMarker) }

    func rebuildMenu() {
        let off = isDisabled()
        // Template (monochrome white) shield; a slashed shield when DLP is off.
        if let img = NSImage(systemSymbolName: off ? "shield.slash" : "shield.fill", accessibilityDescription: "scdlp") {
            img.isTemplate = true
            statusItem.button?.image = img
        } else {
            statusItem.button?.title = off ? "scdlp(off)" : "scdlp"
        }
        let m = NSMenu()
        m.addItem(withTitle: off ? "scdlp — DISABLED" : "scdlp — protecting", action: nil, keyEquivalent: "")
        m.addItem(withTitle: "Approvals handled: \(decisions)", action: nil, keyEquivalent: "")
        m.addItem(.separator())
        m.addItem(withTitle: "Open scdlp…", action: #selector(openDashboard), keyEquivalent: "o").target = self
        let toggle = m.addItem(withTitle: off ? "Enable protection" : "Disable protection",
                               action: #selector(toggleDisabled), keyEquivalent: "")
        toggle.target = self
        m.addItem(.separator())
        m.addItem(withTitle: "Quit scdlp-helper", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        statusItem.menu = m
    }

    @objc func toggleDisabled() {
        if isDisabled() {
            try? FileManager.default.removeItem(atPath: disabledMarker)
        } else {
            try? FileManager.default.createDirectory(atPath: controlDir, withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: disabledMarker, contents: Data())
        }
        rebuildMenu()
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
        // Brand the prompt with a shield instead of the default caution triangle.
        let iconCfg = NSImage.SymbolConfiguration(pointSize: 56, weight: .semibold)
            .applying(NSImage.SymbolConfiguration(paletteColors: [.systemBlue]))
        if let shield = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "SCDLP")?
            .withSymbolConfiguration(iconCfg) {
            shield.isTemplate = false
            alert.icon = shield
        }
        alert.messageText = "Allow \(exe) to read a secret file?"
        alert.informativeText = """
        File: \(req.path)
        Category: \(req.category)
        Process: \(req.human_chain.isEmpty ? req.exe : req.human_chain) (pid \(req.pid))
        """
        alert.addButton(withTitle: "Deny")
        alert.addButton(withTitle: "Allow")

        let app = responsibleApp(fromChain: req.human_chain)
        var scopes = ["Just this once", "Always — for \(exe) (any launch)", "Always — for this exact process"]
        let trustIndex = app.isEmpty ? -1 : scopes.count
        if !app.isEmpty { scopes.append("Always — trust the app “\(app)” completely") }
        let scope = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 360, height: 25), pullsDown: false)
        scope.addItems(withTitles: scopes)
        scope.selectItem(at: 1)
        alert.accessoryView = scope
        NSApp.activate(ignoringOtherApps: true)
        let resp = alert.runModal()

        let idx = scope.indexOfSelectedItem
        let decision = (resp == .alertSecondButtonReturn) ? "allow" : "deny"
        var scopeStr = "once"
        if decision == "allow", idx == trustIndex {
            // Trust the whole app: persist it to the policy + allow this read now.
            addTrustedApp(app)
        } else {
            scopeStr = ["once", "always-exe", "always"][min(max(idx, 0), 2)]
        }
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
