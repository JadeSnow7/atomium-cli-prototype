import AppKit
import BoxCore
import Darwin
import Foundation

@main
struct AtomiumBoxAgent {
    static let maxPayloadBytes = 1024 * 1024 // 1 MiB plain-text cap per spec §4.4

    static func main() {
        var boxIdRaw: String?
        var allowedHostUid: UInt32?
        var keychainSecretFile: String?

        let args = Array(CommandLine.arguments.dropFirst())
        var idx = 0
        while idx < args.count {
            switch args[idx] {
            case "--box":
                idx += 1
                if idx < args.count { boxIdRaw = args[idx] }
            case "--allow-uid":
                idx += 1
                if idx < args.count { allowedHostUid = UInt32(args[idx]) }
            case "--secret-file":
                idx += 1
                if idx < args.count { keychainSecretFile = args[idx] }
            default:
                break
            }
            idx += 1
        }

        guard let boxIdRaw, let boxId = try? BoxIdentifier(boxIdRaw) else {
            fputs("Usage: atomium-box-agent --box <box_id> [--allow-uid <host_uid>] [--secret-file <path>]\n", stderr)
            exit(2)
        }

        let socketPath = boxId.socketPath
        unlink(socketPath)

        let serverFd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverFd >= 0 else {
            fputs("socket(AF_UNIX) failed: errno=\(errno)\n", stderr)
            exit(1)
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8CString)
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            fputs("Socket path too long: \(socketPath)\n", stderr)
            exit(1)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for i in 0..<pathBytes.count {
                rawBuf[i] = UInt8(bitPattern: pathBytes[i])
            }
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let bindRc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverFd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindRc == 0 else {
            fputs("bind(\(socketPath)) failed: errno=\(errno)\n", stderr)
            exit(1)
        }
        _ = chmod(socketPath, 0o660)

        guard listen(serverFd, 8) == 0 else {
            fputs("listen failed: errno=\(errno)\n", stderr)
            exit(1)
        }

        while true {
            let clientFd = accept(serverFd, nil, nil)
            if clientFd < 0 {
                if errno == EINTR { continue }
                break
            }
            handleClient(
                fd: clientFd,
                boxId: boxId,
                allowedHostUid: allowedHostUid,
                keychainSecretFile: keychainSecretFile
            )
            close(clientFd)
        }
    }

    static func handleClient(
        fd: Int32,
        boxId: BoxIdentifier,
        allowedHostUid: UInt32?,
        keychainSecretFile: String?
    ) {
        var peerUid: uid_t = UInt32.max
        var peerGid: gid_t = UInt32.max
        guard getpeereid(fd, &peerUid, &peerGid) == 0 else {
            sendResponse(fd: fd, AgentResponse(ok: false, op: "auth", error: "getpeereid_failed"))
            return
        }

        let authorized = (peerUid == 0) || (allowedHostUid != nil && peerUid == allowedHostUid)
        guard authorized else {
            sendResponse(fd: fd, AgentResponse(ok: false, op: "auth", error: "unauthorized_peer_uid_\(peerUid)"))
            return
        }

        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 8192)
        while buffer.count <= maxPayloadBytes + 4096 {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buffer.append(contentsOf: chunk[0..<n])
            if buffer.contains(0x0A) { break }
        }

        guard let newlineIdx = buffer.firstIndex(of: 0x0A) else {
            sendResponse(fd: fd, AgentResponse(ok: false, op: "unknown", error: "missing_ndjson_newline_or_too_large"))
            return
        }
        let lineData = buffer.subdata(in: 0..<newlineIdx)
        guard let req = try? JSONDecoder().decode(AgentRequest.self, from: lineData) else {
            sendResponse(fd: fd, AgentResponse(ok: false, op: "unknown", error: "invalid_json"))
            return
        }

        switch req.op {
        case "health":
            sendResponse(fd: fd, AgentResponse(ok: true, op: "health", text: "uid=\(geteuid()) box=\(boxId.boxId)"))
        case "clip.set":
            guard let text = req.text else {
                sendResponse(fd: fd, AgentResponse(ok: false, op: "clip.set", error: "missing_text"))
                return
            }
            guard text.utf8.count <= maxPayloadBytes else {
                sendResponse(fd: fd, AgentResponse(ok: false, op: "clip.set", error: "exceeds_1mib_limit"))
                return
            }
            let pb = NSPasteboard.general
            pb.clearContents()
            let ok = pb.setString(text, forType: .string)
            sendResponse(fd: fd, AgentResponse(ok: ok, op: "clip.set", error: ok ? nil : "pasteboard_write_failed"))
        case "clip.get":
            let text = NSPasteboard.general.string(forType: .string) ?? ""
            if text.utf8.count > maxPayloadBytes {
                sendResponse(fd: fd, AgentResponse(ok: false, op: "clip.get", error: "exceeds_1mib_limit"))
                return
            }
            sendResponse(fd: fd, AgentResponse(ok: true, op: "clip.get", text: text))
        case "keychain.unlock":
            guard let secretFile = keychainSecretFile,
                  let rawSecret = try? String(contentsOfFile: secretFile, encoding: .utf8) else {
                sendResponse(fd: fd, AgentResponse(ok: false, op: "keychain.unlock", error: "missing_secret_file"))
                return
            }
            let secret = rawSecret.trimmingCharacters(in: .whitespacesAndNewlines)
            let kcPath = "\(boxId.homeDirectory)/Library/Keychains/login.keychain-db"
            let cmd = SecurityCommandBuilder.unlockKeychain(keychainPath: kcPath, password: secret)
            let res = try? ProcessRunner.runWithTimeout(cmd, timeoutSeconds: 4.0)
            let ok = res?.succeeded ?? false
            sendResponse(fd: fd, AgentResponse(ok: ok, op: "keychain.unlock", error: ok ? nil : "unlock_failed"))
        default:
            sendResponse(fd: fd, AgentResponse(ok: false, op: req.op, error: "unsupported_op"))
        }
    }

    static func sendResponse(fd: Int32, _ resp: AgentResponse) {
        guard var data = try? JSONEncoder().encode(resp) else { return }
        data.append(0x0A)
        _ = data.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                return write(fd, base, ptr.count)
            }
            return 0
        }
    }
}
