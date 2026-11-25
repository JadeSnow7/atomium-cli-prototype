import AppKit
import BoxCore
import CoreGraphics
import Darwin
import Foundation

@MainActor
final class OverlayController: NSObject {
    let boxId: BoxIdentifier
    let targetUid: UInt32
    let borderColor: NSColor
    private var trackedPids: Set<Int32> = []
    private var borderWindows: [CGWindowID: NSWindow] = [:]
    private var pidTimer: Timer?
    private var frameTimer: Timer?

    init(boxId: BoxIdentifier, targetUid: UInt32, borderColor: NSColor) {
        self.boxId = boxId
        self.targetUid = targetUid
        self.borderColor = borderColor
        super.init()
    }

    func start() {
        refreshPids()
        pidTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshPids() }
        }
        frameTimer = Timer.scheduledTimer(withTimeInterval: 0.016, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.syncWindows() }
        }
    }

    func refreshPids() {
        trackedPids = Self.pidsForUid(targetUid)
    }

    static nonisolated func pidsForUid(_ uid: UInt32) -> Set<Int32> {
        let maxCount = proc_listallpids(nil, 0)
        guard maxCount > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(maxCount) + 64)
        let bytes = Int32(pids.count * MemoryLayout<pid_t>.size)
        let actualBytes = proc_listallpids(&pids, bytes)
        guard actualBytes > 0 else { return [] }
        let count = Int(actualBytes) / MemoryLayout<pid_t>.size

        var matched = Set<Int32>()
        let infoSize = Int32(MemoryLayout<proc_bsdinfo>.size)
        for i in 0..<count {
            let pid = pids[i]
            if pid <= 0 { continue }
            var info = proc_bsdinfo()
            let got = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, infoSize)
            if got == infoSize && info.pbi_uid == uid {
                matched.insert(pid)
            }
        }
        return matched
    }

    func syncWindows() {
        guard let rawList = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] else {
            return
        }
        guard let mainScreenHeight = NSScreen.screens.first?.frame.height else { return }

        var activeIds = Set<CGWindowID>()
        for entry in rawList {
            guard let ownerPid = entry[kCGWindowOwnerPID as String] as? Int32,
                  trackedPids.contains(ownerPid),
                  let winNum = entry[kCGWindowNumber as String] as? UInt32,
                  let layer = entry[kCGWindowLayer as String] as? Int32,
                  layer == 0,
                  let boundsDict = entry[kCGWindowBounds as String] as? NSDictionary else {
                continue
            }
            var cgRect = CGRect.zero
            guard CGRectMakeWithDictionaryRepresentation(boundsDict, &cgRect),
                  cgRect.width >= 80, cgRect.height >= 60 else {
                continue
            }

            let winId = CGWindowID(winNum)
            activeIds.insert(winId)

            let cocoaY = mainScreenHeight - (cgRect.origin.y + cgRect.height)
            let expanded = NSRect(
                x: cgRect.origin.x - 3,
                y: cocoaY - 3,
                width: cgRect.width + 6,
                height: cgRect.height + 6
            )

            let overlay = borderWindows[winId] ?? makeOverlayWindow(frame: expanded)
            borderWindows[winId] = overlay
            overlay.setFrame(expanded, display: true)
            overlay.order(.above, relativeTo: Int(winId))
        }

        for (winId, window) in borderWindows where !activeIds.contains(winId) {
            window.orderOut(nil)
            borderWindows.removeValue(forKey: winId)
        }
    }

    private func makeOverlayWindow(frame: NSRect) -> NSWindow {
        let win = NSWindow(contentRect: frame, styleMask: [.borderless], backing: .buffered, defer: false)
        win.isOpaque = false
        win.backgroundColor = .clear
        win.ignoresMouseEvents = true
        win.hasShadow = false
        win.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]

        let view = BorderBadgeView(frame: NSRect(origin: .zero, size: frame.size), label: "BOX: \(boxId.boxId)", color: borderColor)
        view.autoresizingMask = [.width, .height]
        win.contentView = view
        return win
    }
}

final class BorderBadgeView: NSView {
    let label: String
    let color: NSColor

    init(frame: NSRect, label: String, color: NSColor) {
        self.label = label
        self.color = color
        super.init(frame: frame)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("unavailable")
    }

    override func draw(_ dirtyRect: NSRect) {
        let inset = bounds.insetBy(dx: 1.5, dy: 1.5)
        let path = NSBezierPath(roundedRect: inset, xRadius: 10, yRadius: 10)
        path.lineWidth = 3.0
        color.setStroke()
        path.stroke()

        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.boldSystemFont(ofSize: 11),
            .foregroundColor: NSColor.white,
        ]
        let textSize = (label as NSString).size(withAttributes: attrs)
        let badgeRect = NSRect(
            x: 8,
            y: bounds.height - textSize.height - 8,
            width: textSize.width + 12,
            height: textSize.height + 4
        )
        let badgePath = NSBezierPath(roundedRect: badgeRect, xRadius: 4, yRadius: 4)
        color.setFill()
        badgePath.fill()
        (label as NSString).draw(at: NSPoint(x: badgeRect.minX + 6, y: badgeRect.minY + 2), withAttributes: attrs)
    }
}

@main
struct AtomiumBoxOverlay {
    static func parseHexColor(_ hex: String) -> NSColor {
        let clean = hex.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        guard clean.count == 6, let rgb = UInt32(clean, radix: 16) else {
            return NSColor.systemOrange
        }
        let r = CGFloat((rgb >> 16) & 0xFF) / 255.0
        let g = CGFloat((rgb >> 8) & 0xFF) / 255.0
        let b = CGFloat(rgb & 0xFF) / 255.0
        return NSColor(srgbRed: r, green: g, blue: b, alpha: 0.95)
    }

    static func resolveUid(for id: BoxIdentifier) -> UInt32? {
        guard let res = try? ProcessRunner.run(DsclCommandBuilder.readUser(shortName: id.shortName, key: "UniqueID")),
              res.succeeded,
              let raw = DsclParser.parseSingleAttribute(res.stdout, key: "UniqueID") else {
            return nil
        }
        return UInt32(raw)
    }

    static func main() {
        var rawBoxId: String?
        var colorHex = "#FF6B00"
        var inspectOnly = false

        let args = Array(CommandLine.arguments.dropFirst())
        var idx = 0
        while idx < args.count {
            switch args[idx] {
            case "--box":
                idx += 1
                if idx < args.count { rawBoxId = args[idx] }
            case "--color":
                idx += 1
                if idx < args.count { colorHex = args[idx] }
            case "--inspect":
                inspectOnly = true
            default:
                break
            }
            idx += 1
        }

        guard let rawBoxId, let boxId = try? BoxIdentifier(rawBoxId) else {
            fputs("Usage: atomium-box-overlay --box <id> [--color #RRGGBB] [--inspect]\n", stderr)
            exit(2)
        }
        guard let uid = resolveUid(for: boxId) else {
            fputs("Could not resolve UID for \(boxId.shortName)\n", stderr)
            exit(1)
        }

        if inspectOnly {
            let pids = OverlayController.pidsForUid(uid)
            let onScreen = (CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? [])
                .filter { ($0[kCGWindowOwnerPID as String] as? Int32).map(pids.contains) ?? false }
            let allWins = (CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? [])
                .filter { ($0[kCGWindowOwnerPID as String] as? Int32).map(pids.contains) ?? false }
            print("{\"box_id\":\"\(boxId.boxId)\",\"uid\":\(uid),\"pid_count\":\(pids.count),\"onscreen_windows\":\(onScreen.count),\"total_windows\":\(allWins.count)}")
            exit(0)
        }

        MainActor.assumeIsolated {
            let app = NSApplication.shared
            app.setActivationPolicy(.accessory)
            let controller = OverlayController(boxId: boxId, targetUid: uid, borderColor: parseHexColor(colorHex))
            controller.start()
            withExtendedLifetime(controller) {
                app.run()
            }
        }
    }
}
