// scdlp-helper — the user-session menu bar app and approval prompt UI.
//
// It watches the prompt spool written by the (root) system extension, shows an
// Allow/Deny alert for each blocked access, and writes the reply back. It also
// touches a heartbeat file so the extension knows a prompt UI is available
// (when it isn't, the extension fails open instead of silently denying).
import Cocoa
import Foundation

let spoolDir = "/Library/Application Support/scdlp/prompts"
let heartbeatPath = "\(spoolDir)/.helper-alive"

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

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var pollTimer: Timer?
    var heartbeatTimer: Timer?
    var busy = false
    var decisions = 0

    func applicationDidFinishLaunching(_ note: Notification) {
        NSApp.setActivationPolicy(.accessory) // menu bar only, no Dock icon

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🛡"
        rebuildMenu(status: "watching")

        touchHeartbeat()
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.touchHeartbeat()
        }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    func touchHeartbeat() {
        // createFile truncates/updates mtime; no-op if the spool dir is absent.
        _ = FileManager.default.createFile(atPath: heartbeatPath, contents: Data())
    }

    func rebuildMenu(status: String) {
        let m = NSMenu()
        m.addItem(withTitle: "scdlp — \(status)", action: nil, keyEquivalent: "")
        m.addItem(withTitle: "Approvals handled: \(decisions)", action: nil, keyEquivalent: "")
        m.addItem(.separator())
        m.addItem(withTitle: "Quit scdlp-helper", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        statusItem.menu = m
    }

    func poll() {
        guard !busy else { return }
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: spoolDir) else { return }
        for name in names.sorted() where name.hasSuffix(".req.json") {
            let id = String(name.dropLast(".req.json".count))
            let reqPath = "\(spoolDir)/\(name)"
            let replyPath = "\(spoolDir)/\(id).reply.json"
            if fm.fileExists(atPath: replyPath) { continue } // already answered
            guard let data = fm.contents(atPath: reqPath),
                  let req = try? JSONDecoder().decode(Request.self, from: data) else { continue }
            busy = true
            present(req, replyPath: replyPath)
            busy = false
        }
    }

    func present(_ req: Request, replyPath: String) {
        let exe = lastComponent(req.exe)
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Allow \(exe) to read a secret file?"
        alert.informativeText = """
        File: \(req.path)
        Category: \(req.category)
        Process: \(req.human_chain.isEmpty ? req.exe : req.human_chain) (pid \(req.pid))
        """
        alert.addButton(withTitle: "Deny")  // rightmost / default — safe choice
        alert.addButton(withTitle: "Allow")

        let scopePopup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 340, height: 25), pullsDown: false)
        scopePopup.addItems(withTitles: [
            "Just this once",
            "Always — for \(exe) (any launch)",
            "Always — for this exact process",
        ])
        scopePopup.selectItem(at: 1) // default: by app (leaf exe)
        alert.accessoryView = scopePopup

        NSApp.activate(ignoringOtherApps: true)
        let resp = alert.runModal()

        let decision = (resp == .alertSecondButtonReturn) ? "allow" : "deny"
        let scope: String
        switch scopePopup.indexOfSelectedItem {
        case 0: scope = "once"
        case 2: scope = "always"
        default: scope = "always-exe"
        }
        write(Reply(decision: decision, scope: scope), to: replyPath)

        decisions += 1
        rebuildMenu(status: "watching")
    }

    func write(_ reply: Reply, to path: String) {
        guard let data = try? JSONEncoder().encode(reply) else { return }
        try? data.write(to: URL(fileURLWithPath: path))
    }

    func lastComponent(_ p: String) -> String { (p as NSString).lastPathComponent }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
