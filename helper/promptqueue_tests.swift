// Standalone test runner for PromptQueue (the helper's prompt-dedup logic).
// Headless: imports only Foundation, no Cocoa. Compile + run with:
//   swiftc helper/promptqueue.swift helper/promptqueue_tests.swift -o /tmp/pqtest && /tmp/pqtest
// (helper/test.sh wraps this.) Exits non-zero if any assertion fails.
import Foundation

@main
struct PromptQueueTests {
    static func main() {
        var failures = 0
        func check(_ cond: Bool, _ msg: String) {
            if cond {
                print("ok   - \(msg)")
            } else {
                print("FAIL - \(msg)")
                failures += 1
            }
        }

        let t0 = Date(timeIntervalSince1970: 1_000_000)
        func req(_ id: String, ageSec: TimeInterval = 0, reply: Bool = false) -> PendingRequest {
            PendingRequest(id: id, mtime: t0.addingTimeInterval(-ageSec), hasReply: reply)
        }

        // 1. An already-presented id is never returned again — the core re-display fix.
        do {
            let d = PromptQueue.next(requests: [req("a")], presented: ["a"], busy: false, now: t0)
            check(d.present == nil, "already-presented id is not re-presented")
        }

        // 1b. The race: a presented request whose reply file was cleaned
        //     (hasReply=false) must still never re-show.
        do {
            let d = PromptQueue.next(requests: [req("a", reply: false)], presented: ["a"], busy: false, now: t0)
            check(d.present == nil, "presented id with no reply on disk is still not re-shown")
        }

        // 2. Only one prompt is returned per pass, and it's the oldest by mtime.
        do {
            let d = PromptQueue.next(
                requests: [req("new", ageSec: 1), req("old", ageSec: 5), req("mid", ageSec: 3)],
                presented: [], busy: false, now: t0)
            check(d.present == "old", "presents exactly the oldest pending request")
        }

        // 3. Stale requests (older than 30s) are removed and never presented.
        do {
            let d = PromptQueue.next(requests: [req("stale", ageSec: 45)], presented: [], busy: false, now: t0)
            check(d.removeStale == ["stale"], "stale request is queued for removal")
            check(d.present == nil, "stale request is not presented")
        }

        // 4. When a modal is already up (busy), present nothing — but still reap stale ones.
        do {
            let d = PromptQueue.next(
                requests: [req("live", ageSec: 1), req("stale", ageSec: 45)],
                presented: [], busy: true, now: t0)
            check(d.present == nil, "busy ⇒ no second modal")
            check(d.removeStale == ["stale"], "busy still reaps stale requests")
        }

        // 5. A request that already has a reply on disk is skipped.
        do {
            let d = PromptQueue.next(requests: [req("answered", reply: true)], presented: [], busy: false, now: t0)
            check(d.present == nil, "request with a reply is not re-presented")
        }

        // 6. prune keeps only presented ids that still exist on disk (bounds memory).
        do {
            let kept = PromptQueue.prune(presented: ["a", "b", "gone"], existing: ["a", "b", "c"])
            check(kept == ["a", "b"], "prune drops presented ids whose request file is gone")
        }

        if failures == 0 {
            print("\nALL PASS")
        } else {
            print("\n\(failures) FAILURE(S)")
            exit(1)
        }
    }
}
