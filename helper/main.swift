// scdlp-helper — the user-session menu bar app and approval prompt UI.
//
// It watches the prompt spool written by the (root) system extension, shows an
// Allow/Deny alert for each blocked access, and writes the reply back. The
// extension turns an "Always" reply into a persistent rule.
import Cocoa
import Foundation

let spoolDir = "/Library/Application Support/scdlp/prompts"

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
    let scope: String    // "once" | "always"
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var timer: Timer?
    var busy = false
    var decisions = 0

    func applicationDidFinishLaunching(_ note: Notification) {
        NSApp.setActivationPolicy(.accessory) // menu bar only, no Dock icon

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🛡"
        rebuildMenu(status: "watching")

        timer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
            self?.poll()
        }
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
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Allow \(lastComponent(req.exe)) to read a secret file?"
        alert.informativeText = """
        File: \(req.path)
        Category: \(req.category)
        Process: \(req.human_chain.isEmpty ? req.exe : req.human_chain) (pid \(req.pid))
        """
        alert.addButton(withTitle: "Deny")  // rightmost / default — safe choice
        alert.addButton(withTitle: "Allow")

        let remember = NSButton(checkboxWithTitle: "Remember my choice (create a rule)", target: nil, action: nil)
        remember.state = .on
        alert.accessoryView = remember

        NSApp.activate(ignoringOtherApps: true)
        let resp = alert.runModal()

        let decision = (resp == .alertSecondButtonReturn) ? "allow" : "deny"
        let scope = (remember.state == .on) ? "always" : "once"
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
