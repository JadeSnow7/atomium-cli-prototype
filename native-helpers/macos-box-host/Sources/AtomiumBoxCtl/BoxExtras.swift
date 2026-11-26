import BoxCore
import CryptoKit
import Darwin
import Foundation

struct KeychainInitReport: Codable {
    let boxId: String
    let keychainPath: String
    let created: Bool
    let unlocked: Bool
    let listOutput: String

    enum CodingKeys: String, CodingKey {
        case boxId = "box_id"
        case keychainPath = "keychain_path"
        case created
        case unlocked
        case listOutput = "list_output"
    }
}

struct GiveFileReport: Codable {
    let boxId: String
    let sourcePath: String
    let destinationPath: String
    let byteCount: Int
    let sha256Digest: String
    let mode: String

    enum CodingKeys: String, CodingKey {
        case boxId = "box_id"
        case sourcePath = "source_path"
        case destinationPath = "destination_path"
        case byteCount = "byte_count"
        case sha256Digest = "sha256_digest"
        case mode
    }
}

struct FullProbeOrchestrationReport: Codable {
    let boxId: String
    let peerBoxId: String?
    let hostUser: String
    let baselineV1: ProbeSuiteReport
    let baselineAsuser: ProbeSuiteReport
    let sbplPrimaryCompiled: Bool
    let sbplPrimaryProfile: String
    let sbplPrimaryStderr: String
    let sbplPatchedReport: ProbeSuiteReport?
    let sbplFallbackUsed: Bool
    let sbplFallbackProfile: String?

    enum CodingKeys: String, CodingKey {
        case boxId = "box_id"
        case peerBoxId = "peer_box_id"
        case hostUser = "host_user"
        case baselineV1 = "baseline_v1"
        case baselineAsuser = "baseline_asuser"
        case sbplPrimaryCompiled = "sbpl_primary_compiled"
        case sbplPrimaryProfile = "sbpl_primary_profile"
        case sbplPrimaryStderr = "sbpl_primary_stderr"
        case sbplPatchedReport = "sbpl_patched_report"
        case sbplFallbackUsed = "sbpl_fallback_used"
        case sbplFallbackProfile = "sbpl_fallback_profile"
    }
}

enum BoxExtras {
    static func siblingBinaryPath(_ name: String) throws -> String {
        let selfUrl = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let sibling = selfUrl.deletingLastPathComponent().appendingPathComponent(name).path
        guard FileManager.default.isExecutableFile(atPath: sibling) else {
            throw BoxCLIError.notFound("Helper binary '\(name)' not found next to atomium-boxctl at \(sibling)")
        }
        return sibling
    }

    // MARK: - §4.5 keychain-init

    static func keychainInit(boxId rawBoxId: String) throws -> KeychainInitReport {
        try BoxLifecycle.requireRoot(for: "keychain-init")
        let (identifier, uid, gid) = try BoxLauncher.resolveManagedBox(rawBoxId)

        guard let rawSecret = try? String(contentsOfFile: identifier.secretPath, encoding: .utf8) else {
            throw BoxCLIError.notFound("Missing Box secret file at \(identifier.secretPath)")
        }
        let secret = rawSecret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !secret.isEmpty else {
            throw BoxCLIError.internalError("Empty secret in \(identifier.secretPath)")
        }

        let keychainsDir = "\(identifier.homeDirectory)/Library/Keychains"
        let kcPath = "\(keychainsDir)/login.keychain-db"
        let createKeychain = try SecurityCommandBuilder.createKeychain(keychainPath: kcPath, password: secret, expectedDirectory: keychainsDir)
        let unlockKeychain = try SecurityCommandBuilder.unlockKeychain(keychainPath: kcPath, password: secret, expectedDirectory: keychainsDir)
        try BoxKeychainDirectory.prepare(homeDirectory: identifier.homeDirectory, uid: uid, gid: gid)
        let env = BoxLauncher.boxRuntimeEnvironment(identifier: identifier)

        func runSecurityAsBox(_ secArgs: [String], redacted: [String]? = nil, stdinData: Data? = nil) throws -> ProcessResult {
            let prefix = ["/bin/launchctl", "asuser", String(uid), "/usr/bin/sudo", "-u", identifier.shortName, "-H"]
                + LaunchctlCommandBuilder.boxEnvironmentPrefix(id: identifier)
                + ["/usr/bin/security"]
            let spec = CommandSpec(
                executable: "/usr/bin/sudo",
                arguments: prefix + secArgs,
                redactedArguments: redacted.map { prefix + $0 },
                stdinData: stdinData
            )
            return try ProcessRunner.runWithTimeout(spec, timeoutSeconds: 8.0, environment: env, currentDirectoryPath: identifier.homeDirectory)
        }

        let createRes = try runSecurityAsBox(
            createKeychain.arguments,
            redacted: createKeychain.redactedArguments,
            stdinData: createKeychain.stdinData
        )
        guard createRes.succeeded else {
            throw BoxCLIError.commandFailed("security create-keychain", "exit=\(createRes.exitCode), timed_out=\(createRes.timedOut)")
        }

        _ = try runSecurityAsBox(["default-keychain", "-d", "user", "-s", kcPath])
        _ = try runSecurityAsBox(["login-keychain", "-d", "user", "-s", kcPath])
        _ = try runSecurityAsBox(["set-keychain-settings", kcPath])

        let unlockRes = try runSecurityAsBox(
            unlockKeychain.arguments,
            redacted: unlockKeychain.redactedArguments,
            stdinData: unlockKeychain.stdinData
        )
        guard !unlockRes.timedOut else {
            throw BoxCLIError.commandFailed("security unlock-keychain", "timed out")
        }
        let listRes = try runSecurityAsBox(["list-keychains", "-d", "user"])

        return KeychainInitReport(
            boxId: identifier.boxId,
            keychainPath: kcPath,
            created: createRes.succeeded,
            unlocked: unlockRes.succeeded,
            listOutput: listRes.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    // MARK: - §4.6 give-file

    static func giveFile(boxId rawBoxId: String, hostPath: String) throws -> GiveFileReport {
        try BoxLifecycle.requireRoot(for: "give-file")
        let (identifier, uid, gid) = try BoxLauncher.resolveManagedBox(rawBoxId)

        var st = stat()
        guard lstat(hostPath, &st) == 0 else {
            throw BoxCLIError.notFound("Host path does not exist: \(hostPath)")
        }
        let fileType = st.st_mode & S_IFMT
        if fileType == S_IFLNK {
            throw BoxCLIError.guardrailRejected("Refusing symlink in give-file: \(hostPath)")
        }
        if fileType == S_IFDIR {
            throw BoxCLIError.guardrailRejected("Refusing directory in give-file (single regular file only): \(hostPath)")
        }
        guard fileType == S_IFREG else {
            throw BoxCLIError.guardrailRejected("Refusing special non-regular file in give-file: \(hostPath)")
        }

        let fm = FileManager.default
        if !fm.fileExists(atPath: identifier.inboxDirectory) {
            try fm.createDirectory(atPath: identifier.inboxDirectory, withIntermediateDirectories: true)
        }
        try BoxLifecycle.setOwnerAndMode(path: identifier.inboxDirectory, uid: uid, gid: gid, mode: 0o700)

        let fileName = (hostPath as NSString).lastPathComponent
        let destPath = (identifier.inboxDirectory as NSString).appendingPathComponent(fileName)
        let data = try Data(contentsOf: URL(fileURLWithPath: hostPath))
        try data.write(to: URL(fileURLWithPath: destPath), options: .atomic)
        try BoxLifecycle.setOwnerAndMode(path: destPath, uid: uid, gid: gid, mode: 0o600)

        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let mode = try BoxLifecycle.octalPermissions(of: destPath)

        return GiveFileReport(
            boxId: identifier.boxId,
            sourcePath: hostPath,
            destinationPath: destPath,
            byteCount: data.count,
            sha256Digest: "sha256:\(digest)",
            mode: mode
        )
    }

    // MARK: - §4.8 & §4.9 probe

    static func runFullProbe(
        boxId rawBoxId: String,
        peerBoxId rawPeerBoxId: String?,
        clipboardMarker: String?
    ) throws -> FullProbeOrchestrationReport {
        try BoxLifecycle.requireRoot(for: "probe")
        let (identifier, uid, gid) = try BoxLauncher.resolveManagedBox(rawBoxId)
        let env = try BoxLauncher.prepareBoxRuntimeEnvironment(identifier: identifier, uid: uid, gid: gid)

        guard let hostUser = ProcessInfo.processInfo.environment["SUDO_USER"], !hostUser.isEmpty,
              let hostUidRaw = ProcessInfo.processInfo.environment["SUDO_UID"], let hostUid = UInt32(hostUidRaw),
              let hostGidRaw = ProcessInfo.processInfo.environment["SUDO_GID"], let hostGid = UInt32(hostGidRaw) else {
            throw BoxCLIError.invalidArguments("probe must be invoked via sudo from the host user's Terminal (SUDO_USER/SUDO_UID required)")
        }

        let probeBin = try siblingBinaryPath("atomium-box-probe")
        let agentBin = try siblingBinaryPath("atomium-box-agent")

        // Copy probe & agent into /private/var/atomium-proto/bin (0755 root:wheel) so Box users can execute them
        // even when the workspace lives under /Users/<host_user> (0700)!
        let sharedBinDir = "/private/var/atomium-proto/bin"
        let fm = FileManager.default
        try fm.createDirectory(atPath: "/private/var/atomium-proto", withIntermediateDirectories: true)
        try BoxLifecycle.setOwnerAndMode(path: "/private/var/atomium-proto", uid: 0, gid: 0, mode: 0o755)
        try fm.createDirectory(atPath: sharedBinDir, withIntermediateDirectories: true)
        try BoxLifecycle.setOwnerAndMode(path: sharedBinDir, uid: 0, gid: 0, mode: 0o755)

        let stagedProbe = "\(sharedBinDir)/atomium-box-probe"
        let stagedAgent = "\(sharedBinDir)/atomium-box-agent"
        for (src, dst) in [(probeBin, stagedProbe), (agentBin, stagedAgent)] {
            if fm.fileExists(atPath: dst) { try fm.removeItem(atPath: dst) }
            try fm.copyItem(atPath: src, toPath: dst)
            try BoxLifecycle.setOwnerAndMode(path: dst, uid: 0, gid: 0, mode: 0o755)
        }

        // Set up temporary /tmp host files (0600 and 0644 owned by hostUid:hostGid) for S2a
        let token = UUID().uuidString.lowercased()
        let tmpPriv = "/tmp/atomium-s2a-priv-\(token).txt"
        let tmpWorld = "/tmp/atomium-s2a-world-\(token).txt"
        try Data("host-private\n".utf8).write(to: URL(fileURLWithPath: tmpPriv))
        try BoxLifecycle.setOwnerAndMode(path: tmpPriv, uid: hostUid, gid: hostGid, mode: 0o600)
        try Data("host-world\n".utf8).write(to: URL(fileURLWithPath: tmpWorld))
        try BoxLifecycle.setOwnerAndMode(path: tmpWorld, uid: hostUid, gid: hostGid, mode: 0o644)
        defer {
            try? fm.removeItem(atPath: tmpPriv)
            try? fm.removeItem(atPath: tmpWorld)
        }

        // Temporary loopback listener on 127.0.0.1:0 for S2g
        let (loopbackFd, loopbackPort) = try openLoopbackListener()
        defer { close(loopbackFd) }

        // Find a safe host PID owned by hostUid (e.g. parent sudo's parent shell or cfprefsd)
        let hostPid = findProcessForUid(hostUid)

        // Optional peer Box agent setup for S2h
        var peerAgentProcess: Process?
        var resolvedPeerId: BoxIdentifier?
        if let rawPeerBoxId {
            let (peerId, peerUid, peerGid) = try BoxLauncher.resolveManagedBox(rawPeerBoxId)
            resolvedPeerId = peerId
            let ctlGid = try BoxLifecycle.ensureGroup(name: BoxConstants.controlGroupName, minGid: BoxConstants.minGid + 50)
            try fm.createDirectory(atPath: BoxConstants.runtimeDirectory, withIntermediateDirectories: true)
            try BoxLifecycle.setOwnerAndMode(path: BoxConstants.runtimeDirectory, uid: 0, gid: 0, mode: 0o755)
            try fm.createDirectory(atPath: peerId.socketDirectory, withIntermediateDirectories: true)
            // Owner peerUid:ctlGid 0750 -> peer Box can bind socket, atombox_ctl/root can traverse, Box A gets EACCES!
            try BoxLifecycle.setOwnerAndMode(path: peerId.socketDirectory, uid: peerUid, gid: ctlGid, mode: 0o750)

            let peerEnv = try BoxLauncher.prepareBoxRuntimeEnvironment(identifier: peerId, uid: peerUid, gid: peerGid)
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            proc.arguments = ["-u", peerId.shortName, "-H"]
                + LaunchctlCommandBuilder.boxEnvironmentPrefix(id: peerId)
                + [stagedAgent, "--box", peerId.boxId, "--allow-uid", String(hostUid)]
            proc.currentDirectoryURL = URL(fileURLWithPath: peerId.homeDirectory, isDirectory: true)
            proc.environment = peerEnv
            proc.standardOutput = FileHandle.nullDevice
            proc.standardError = FileHandle.nullDevice
            try proc.run()
            peerAgentProcess = proc
            Thread.sleep(forTimeInterval: 0.4)
        }
        defer {
            if let proc = peerAgentProcess, proc.isRunning {
                proc.terminate()
                if let resolvedPeerId {
                    _ = try? ProcessRunner.run(CommandSpec(executable: "/usr/bin/pkill", arguments: ["-TERM", "-f", "atomium-box-agent --box \(resolvedPeerId.boxId)"]))
                }
            }
        }

        let peerPid: Int32? = resolvedPeerId.flatMap { peer in
            if let uidStr = BoxLifecycle.readAttribute(user: peer.shortName, key: "UniqueID"),
               let pUid = UInt32(uidStr) {
                return findProcessForUid(pUid)
            }
            return nil
        }

        var probeArgs = [
            "--host-user", hostUser,
            "--host-uid", String(hostUid),
            "--host-tmp-private", tmpPriv,
            "--host-tmp-world", tmpWorld,
            "--host-loopback-port", String(loopbackPort),
        ]
        if let hostPid { probeArgs += ["--host-pid", String(hostPid)] }
        if let clipboardMarker, !clipboardMarker.isEmpty { probeArgs += ["--clipboard-marker", clipboardMarker] }
        if let resolvedPeerId { probeArgs += ["--peer-box", resolvedPeerId.boxId] }
        if let peerPid { probeArgs += ["--peer-pid", String(peerPid)] }

        func invokeProbe(useAsuser: Bool, sbplPath: String?) throws -> ProcessResult {
            var cmd: [String] = []
            if useAsuser {
                cmd += ["/bin/launchctl", "asuser", String(uid)]
            }
            cmd += ["/usr/bin/sudo", "-u", identifier.shortName, "-H"]
            cmd += LaunchctlCommandBuilder.boxEnvironmentPrefix(id: identifier)
            if let sbplPath {
                cmd += ["/usr/bin/sandbox-exec", "-f", sbplPath]
            }
            cmd += [stagedProbe] + probeArgs
            return try ProcessRunner.runWithTimeout(
                CommandSpec(executable: cmd[0], arguments: Array(cmd.dropFirst())),
                timeoutSeconds: 15.0,
                environment: env,
                currentDirectoryPath: identifier.homeDirectory
            )
        }

        let v1Res = try invokeProbe(useAsuser: false, sbplPath: nil)
        guard v1Res.succeeded, let v1Report = try? JSONDecoder().decode(ProbeSuiteReport.self, from: Data(v1Res.stdout.utf8)) else {
            throw BoxCLIError.commandFailed("atomium-box-probe (V1)", v1Res.stderr + "\n" + v1Res.stdout)
        }

        let asuserRes = try invokeProbe(useAsuser: true, sbplPath: nil)
        guard asuserRes.succeeded, let asuserReport = try? JSONDecoder().decode(ProbeSuiteReport.self, from: Data(asuserRes.stdout.utf8)) else {
            throw BoxCLIError.commandFailed("atomium-box-probe (asuser)", asuserRes.stderr + "\n" + asuserRes.stdout)
        }

        // §4.9 SBPL patch test
        let primarySbpl = try SbplBuilder.identityPatchProfile(hostShortName: hostUser, useRegistryClassFallback: false)
        let primarySbplPath = "\(identifier.tmpDirectory)/s2f-patch-primary.sb"
        try Data((primarySbpl + "\n").utf8).write(to: URL(fileURLWithPath: primarySbplPath))
        try BoxLifecycle.setOwnerAndMode(path: primarySbplPath, uid: uid, gid: gid, mode: 0o600)

        let sbplRes = try invokeProbe(useAsuser: true, sbplPath: primarySbplPath)
        var patchedReport: ProbeSuiteReport?
        var fallbackUsed = false
        var fallbackProfileText: String?

        if sbplRes.succeeded, let decoded = try? JSONDecoder().decode(ProbeSuiteReport.self, from: Data(sbplRes.stdout.utf8)) {
            // Check whether iokit-property actually hid serial & UUID; if not, also evaluate registry-entry-class fallback!
            let serialStillVisible = decoded.s2fIdentity["iokit_serial_visible"] == .bool(true)
                || decoded.s2fIdentity["ioreg_serial_visible"] == .bool(true)
            if serialStillVisible {
                let fbSbpl = try SbplBuilder.identityPatchProfile(hostShortName: hostUser, useRegistryClassFallback: true)
                let fbPath = "\(identifier.tmpDirectory)/s2f-patch-fallback.sb"
                try Data((fbSbpl + "\n").utf8).write(to: URL(fileURLWithPath: fbPath))
                try BoxLifecycle.setOwnerAndMode(path: fbPath, uid: uid, gid: gid, mode: 0o600)
                let fbRes = try invokeProbe(useAsuser: true, sbplPath: fbPath)
                if fbRes.succeeded, let fbDecoded = try? JSONDecoder().decode(ProbeSuiteReport.self, from: Data(fbRes.stdout.utf8)) {
                    patchedReport = fbDecoded
                    fallbackUsed = true
                    fallbackProfileText = fbSbpl
                } else {
                    patchedReport = decoded
                }
            } else {
                patchedReport = decoded
            }
        } else {
            let fbSbpl = try SbplBuilder.identityPatchProfile(hostShortName: hostUser, useRegistryClassFallback: true)
            let fbPath = "\(identifier.tmpDirectory)/s2f-patch-fallback.sb"
            try Data((fbSbpl + "\n").utf8).write(to: URL(fileURLWithPath: fbPath))
            try BoxLifecycle.setOwnerAndMode(path: fbPath, uid: uid, gid: gid, mode: 0o600)
            let fbRes = try invokeProbe(useAsuser: true, sbplPath: fbPath)
            if fbRes.succeeded, let fbDecoded = try? JSONDecoder().decode(ProbeSuiteReport.self, from: Data(fbRes.stdout.utf8)) {
                patchedReport = fbDecoded
                fallbackUsed = true
                fallbackProfileText = fbSbpl
            }
        }

        return FullProbeOrchestrationReport(
            boxId: identifier.boxId,
            peerBoxId: resolvedPeerId?.boxId,
            hostUser: hostUser,
            baselineV1: v1Report,
            baselineAsuser: asuserReport,
            sbplPrimaryCompiled: sbplRes.succeeded,
            sbplPrimaryProfile: primarySbpl,
            sbplPrimaryStderr: sbplRes.stderr.trimmingCharacters(in: .whitespacesAndNewlines),
            sbplPatchedReport: patchedReport,
            sbplFallbackUsed: fallbackUsed,
            sbplFallbackProfile: fallbackProfileText
        )
    }

    static func openLoopbackListener() throws -> (Int32, UInt16) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw BoxCLIError.internalError("socket(AF_INET) failed: errno=\(errno)")
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)

        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0, listen(fd, 4) == 0 else {
            close(fd)
            throw BoxCLIError.internalError("bind/listen 127.0.0.1:0 failed: errno=\(errno)")
        }

        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        return (fd, UInt16(bigEndian: bound.sin_port))
    }

    static func findProcessForUid(_ uid: UInt32) -> Int32? {
        guard let res = try? ProcessRunner.run(
            CommandSpec(executable: "/bin/ps", arguments: ["-u", String(uid), "-o", "pid="])
        ), res.succeeded else {
            return nil
        }
        for line in res.stdout.split(whereSeparator: \.isNewline) {
            if let pid = Int32(line.trimmingCharacters(in: .whitespaces)), pid > 1 {
                return pid
            }
        }
        return nil
    }
}
