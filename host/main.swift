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
            exit(0)
        case .willCompleteAfterReboot:
            print("scdlp-host: activation will complete after reboot")
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
