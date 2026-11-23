import Foundation

/// Skeleton for Atomium's standalone macOS WKWebView helper process.
/// Decoupled from Tauri: receives bounded JSON-RPC navigation/preview requests over stdio
/// and uses nonPersistent WKWebsiteDataStore by default.
@main
struct AtomiumBrowserHost {
    static func main() {
        let info = [
            "service": "atomium-browser-host",
            "status": "skeleton-ready",
            "storage": "nonPersistent"
        ]
        if let data = try? JSONSerialization.data(withJSONObject: info),
           let line = String(data: data, encoding: .utf8) {
            print(line)
        }
    }
}
