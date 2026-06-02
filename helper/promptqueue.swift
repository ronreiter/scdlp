// PromptQueue is the helper's prompt-dedup logic, factored out of the Cocoa glue
// so it can be unit-tested headless (Foundation only — see promptqueue_tests.swift).
//
// The menu bar app polls the spool every 0.3s. Before this logic existed, each
// poll dispatched a modal for every pending request, so a single prompt that sat
// on screen for a few seconds spawned a stream of duplicate dialogs (the scan
// kept firing while the main thread was blocked in runModal, and the request/
// reply file cleanup raced). PromptQueue makes the decision deterministic and
// idempotent: at most one modal at a time, and each request id is shown at most
// once for the lifetime of its file.
import Foundation

// PendingRequest is the minimal view of a "<id>.req.json" the decision needs:
// its id, the file's mtime (for staleness), and whether a reply already exists.
struct PendingRequest {
    let id: String
    let mtime: Date
    let hasReply: Bool
}

enum PromptQueue {
    // A request older than this with no reply is abandoned (the accessing process
    // is long gone); we delete it rather than pop a stale popup.
    static let staleAfter: TimeInterval = 30

    struct Decision: Equatable {
        var present: String?      // request id to show now (nil ⇒ show nothing this pass)
        var removeStale: [String] // request ids to delete (too old to act on)
    }

    // next decides what a single scan pass should do, given the requests currently
    // on disk, the ids already shown to the user, whether a modal is up, and now.
    //
    // It NEVER returns an id in `presented` — that is what stops the same dialog
    // from reappearing after the user has answered, even while the request/reply
    // files are still being cleaned up. At most one id is returned per pass.
    static func next(requests: [PendingRequest], presented: Set<String>, busy: Bool, now: Date) -> Decision {
        var d = Decision(present: nil, removeStale: [])

        // Reap stale requests regardless of busy state. Collect the survivors.
        var fresh: [PendingRequest] = []
        for r in requests {
            if now.timeIntervalSince(r.mtime) > staleAfter {
                d.removeStale.append(r.id)
            } else {
                fresh.append(r)
            }
        }

        // One modal at a time: while a prompt is on screen, only reaping happens.
        if busy { return d }

        // Show the oldest request that hasn't been answered and hasn't been shown.
        // Sort by mtime ascending, id as a deterministic tie-breaker.
        for r in fresh.sorted(by: { $0.mtime == $1.mtime ? $0.id < $1.id : $0.mtime < $1.mtime }) {
            if r.hasReply { continue }
            if presented.contains(r.id) { continue }
            d.present = r.id
            break
        }
        return d
    }

    // prune drops presented ids whose request file no longer exists, bounding the
    // set's growth. Safe because request ids are one-shot UUIDs: a deleted id is
    // never reused, so it can never legitimately need to be presented again.
    static func prune(presented: Set<String>, existing: Set<String>) -> Set<String> {
        presented.intersection(existing)
    }
}
