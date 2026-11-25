import AppKit
import BoxCore
import Darwin
import Foundation

@main
struct AtomiumBoxClip {
    static let maxPayloadBytes = 1024 * 1024

    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard args.count >= 2 else {
            fputs("Usage: atomium-box-clip <to-box|from-box|health> <box_id>\n", stderr)
            exit(2)
        }
        let direction = args[0]
        guard let boxId = try? BoxIdentifier(args[1]) else {
            fputs("Invalid box_id: \(args[1])\n", stderr)
            exit(2)
        }

        do {
            switch direction {
            case "to-box":
                let text = NSPasteboard.general.string(forType: .string) ?? ""
                guard text.utf8.count <= maxPayloadBytes else {
                    fputs("Error: clipboard text exceeds 1 MiB limit\n", stderr)
                    exit(1)
                }
                let resp = try send(to: boxId.socketPath, request: AgentRequest(op: "clip.set", text: text))
                guard resp.ok else {
                    fputs("Agent error: \(resp.error ?? "unknown")\n", stderr)
                    exit(1)
                }
                print("Transferred \(text.utf8.count) bytes to Box \(boxId.boxId) clipboard.")
            case "from-box":
                let resp = try send(to: boxId.socketPath, request: AgentRequest(op: "clip.get"))
                guard resp.ok, let text = resp.text else {
                    fputs("Agent error: \(resp.error ?? "unknown")\n", stderr)
                    exit(1)
                }
                let pb = NSPasteboard.general
                pb.clearContents()
                guard pb.setString(text, forType: .string) else {
                    fputs("Error: failed to write to host pasteboard\n", stderr)
                    exit(1)
                }
                print("Transferred \(text.utf8.count) bytes from Box \(boxId.boxId) clipboard to host.")
            case "health":
                let resp = try send(to: boxId.socketPath, request: AgentRequest(op: "health"))
                let data = try JSONEncoder().encode(resp)
                print(String(decoding: data, as: UTF8.self))
                if !resp.ok { exit(1) }
            default:
                fputs("Unknown subcommand: \(direction)\n", stderr)
                exit(2)
            }
        } catch {
            fputs("Error: \(error)\n", stderr)
            exit(1)
        }
    }

    static func send(to socketPath: String, request: AgentRequest) throws -> AgentResponse {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8CString)
        guard bytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(ENAMETOOLONG))
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for i in 0..<bytes.count {
                rawBuf[i] = UInt8(bitPattern: bytes[i])
            }
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var payload = try JSONEncoder().encode(request)
        payload.append(0x0A)
        try payload.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress, write(fd, base, ptr.count) == ptr.count else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
        }

        var responseData = Data()
        var buf = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { break }
            responseData.append(contentsOf: buf[0..<n])
            if responseData.contains(0x0A) { break }
        }
        if let nl = responseData.firstIndex(of: 0x0A) {
            responseData = responseData.subdata(in: 0..<nl)
        }
        return try JSONDecoder().decode(AgentResponse.self, from: responseData)
    }
}
