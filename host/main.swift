import Foundation
import SystemExtensions

let EXTENSION_BUNDLE_ID = "io.sentra.scdlp.extension"

final class Activator: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ req: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("scdlp-host: replacing existing extension v\(existing.bundleShortVersion) with v\(ext.bundleShortVersion)")
        return .replace
    }
    func requestNeedsUserApproval(_ req: OSSystemExtensionRequest) {
        print("scdlp-host: user approval required. Open System Settings > Privacy & Security > Allow.")
    }
    func request(_ req: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            print("scdlp-host: activation completed")
            installHelperAgent()
            exit(0)
        case .willCompleteAfterReboot:
            print("scdlp-host: activation will complete after reboot")
            installHelperAgent()
            exit(0)
        @unknown default:
            print("scdlp-host: activation finished with unknown result")
            exit(1)
        }
    }
    func request(_ req: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("scdlp-host: activation failed: \(error.localizedDescription)")
        exit(2)
    }
}

// installHelperAgent installs + (re)loads a per-user LaunchAgent that runs the
// bundled menu bar helper (the approval-prompt UI) at login and keeps it alive.
// Runs as the user who launched the host app, so it can write ~/Library and
// bootstrap into the user's GUI (Aqua) domain.
func installHelperAgent() {
    let helperExe = Bundle.main.bundlePath
        + "/Contents/Library/scdlp-helper.app/Contents/MacOS/scdlp-helper"
    guard FileManager.default.fileExists(atPath: helperExe) else {
        print("scdlp-host: bundled helper not found at \(helperExe); skipping agent install")
        return
    }
    let agentsDir = NSHomeDirectory() + "/Library/LaunchAgents"
    try? FileManager.default.createDirectory(atPath: agentsDir, withIntermediateDirectories: true)
    let plistPath = agentsDir + "/io.sentra.scdlp.helper.plist"

    let plist: [String: Any] = [
        "Label": "io.sentra.scdlp.helper",
        "ProgramArguments": [helperExe],
        "RunAtLoad": true,
        "KeepAlive": true,
        "LimitLoadToSessionType": "Aqua",
    ]
    guard let data = try? PropertyListSerialization.data(
        fromPropertyList: plist, format: .xml, options: 0) else { return }
    try? data.write(to: URL(fileURLWithPath: plistPath))

    let uid = getuid()
    runLaunchctl(["bootout", "gui/\(uid)/io.sentra.scdlp.helper"]) // ignore errors
    if runLaunchctl(["bootstrap", "gui/\(uid)", plistPath]) {
        print("scdlp-host: prompt helper installed + started")
    } else {
        print("scdlp-host: helper agent written to \(plistPath) (will start at next login)")
    }
}

@discardableResult
func runLaunchctl(_ a: [String]) -> Bool {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    p.arguments = a
    do { try p.run() } catch { return false }
    p.waitUntilExit()
    return p.terminationStatus == 0
}

let args = CommandLine.arguments
let action = args.count > 1 ? args[1] : "activate"

let activator = Activator()
let req: OSSystemExtensionRequest
switch action {
case "activate":
    req = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: EXTENSION_BUNDLE_ID,
        queue: .main
    )
case "deactivate":
    req = OSSystemExtensionRequest.deactivationRequest(
        forExtensionWithIdentifier: EXTENSION_BUNDLE_ID,
        queue: .main
    )
default:
    print("usage: scdlp-host {activate|deactivate}")
    exit(64)
}
req.delegate = activator
OSSystemExtensionManager.shared.submitRequest(req)
RunLoop.main.run()
