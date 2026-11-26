import ApplicationServices
import AVFoundation
import BoxCore
import Contacts
import CoreGraphics
import Darwin
import Foundation
import IOKit
import os
import ScreenCaptureKit

@main
struct AtomiumBoxProbe {
    struct Config {
        var hostUser: String = ""
        var hostUid: UInt32?
        var hostPid: Int32?
        var hostTmpPrivateFile: String?
        var hostTmpWorldFile: String?
        var clipboardMarker: String?
        var hostLoopbackPort: UInt16?
        var peerBoxId: String?
        var peerPid: Int32?
    }

    static func parseArgs() -> Config {
        var cfg = Config()
        let args = Array(CommandLine.arguments.dropFirst())
        var idx = 0
        while idx < args.count {
            switch args[idx] {
            case "--host-user":
                idx += 1
                if idx < args.count { cfg.hostUser = args[idx] }
            case "--host-uid":
                idx += 1
                if idx < args.count { cfg.hostUid = UInt32(args[idx]) }
            case "--host-pid":
                idx += 1
                if idx < args.count { cfg.hostPid = Int32(args[idx]) }
            case "--host-tmp-private":
                idx += 1
                if idx < args.count { cfg.hostTmpPrivateFile = args[idx] }
            case "--host-tmp-world":
                idx += 1
                if idx < args.count { cfg.hostTmpWorldFile = args[idx] }
            case "--clipboard-marker":
                idx += 1
                if idx < args.count { cfg.clipboardMarker = args[idx] }
            case "--host-loopback-port":
                idx += 1
                if idx < args.count { cfg.hostLoopbackPort = UInt16(args[idx]) }
            case "--peer-box":
                idx += 1
                if idx < args.count { cfg.peerBoxId = args[idx] }
            case "--peer-pid":
                idx += 1
                if idx < args.count { cfg.peerPid = Int32(args[idx]) }
            default:
                break
            }
            idx += 1
        }
        return cfg
    }

    static func main() {
        let cfg = parseArgs()
        let euid = geteuid()
        let egid = getegid()
        let boxUser = ProcessInfo.processInfo.environment["USER"] ?? "uid-\(euid)"

        guard euid != 0 else {
            fputs("Refusing to run atomium-box-probe as root (must run as unprivileged Box user)\n", stderr)
            exit(2)
        }
        if let hostUid = cfg.hostUid, euid == hostUid {
            fputs("Refusing to run atomium-box-probe as host UID \(hostUid)\n", stderr)
            exit(2)
        }

        let s2a = runS2aFile(cfg: cfg)
        let s2b = runS2bKeychain(cfg: cfg)
        let s2c = runS2cClipboard(cfg: cfg)
        let s2d = runS2dTcc(cfg: cfg)
        let s2e = runS2eProcess(cfg: cfg)
        let s2f = runS2fIdentity(cfg: cfg)
        let s2g = runS2gNetwork(cfg: cfg)
        let s2h = runS2hCrossBox(cfg: cfg)

        let report = ProbeSuiteReport(
            boxUser: boxUser,
            euid: euid,
            egid: egid,
            s2aFile: s2a,
            s2bKeychain: s2b,
            s2cClipboard: s2c,
            s2dTcc: s2d,
            s2eProcess: s2e,
            s2fIdentity: s2f,
            s2gNetwork: s2g,
            s2hCrossBox: s2h
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        if let data = try? encoder.encode(report) {
            print(String(decoding: data, as: UTF8.self))
        } else {
            fputs("Failed to encode ProbeSuiteReport\n", stderr)
            exit(1)
        }
    }

    // MARK: - Helpers

    static func probeDirectoryRead(_ path: String) -> [String: JSONValue] {
        var dirPtr = opendir(path)
        if dirPtr != nil {
            var count = 0
            while readdir(dirPtr) != nil {
                count += 1
            }
            closedir(dirPtr)
            dirPtr = nil
            return [
                "accessible": .bool(true),
                "entry_count": .int(max(0, count - 2)),
                "errno": .int(0),
                "error": .string("OK"),
            ]
        } else {
            let err = errno
            let name = errnoName(err)
            return [
                "accessible": .bool(false),
                "errno": .int(Int(err)),
                "error": .string(name),
            ]
        }
    }

    static func probeFileRead(_ path: String) -> [String: JSONValue] {
        let fd = open(path, O_RDONLY)
        if fd >= 0 {
            var buf = [UInt8](repeating: 0, count: 64)
            let n = read(fd, &buf, buf.count)
            close(fd)
            return [
                "accessible": .bool(true),
                "bytes_sampled": .int(max(0, n)),
                "errno": .int(0),
                "error": .string("OK"),
            ]
        } else {
            let err = errno
            return [
                "accessible": .bool(false),
                "errno": .int(Int(err)),
                "error": .string(errnoName(err)),
            ]
        }
    }

    static func probeStatMetadata(_ path: String) -> [String: JSONValue] {
        var st = stat()
        if lstat(path, &st) == 0 {
            let modeStr = String(format: "%04o", Int(st.st_mode) & 0o7777)
            return [
                "stat_ok": .bool(true),
                "mode": .string(modeStr),
                "uid": .int(Int(st.st_uid)),
                "errno": .int(0),
            ]
        } else {
            let err = errno
            return [
                "stat_ok": .bool(false),
                "errno": .int(Int(err)),
                "error": .string(errnoName(err)),
            ]
        }
    }

    static func errnoName(_ code: Int32) -> String {
        switch code {
        case EACCES: return "EACCES"
        case EPERM: return "EPERM"
        case ENOENT: return "ENOENT"
        case ESRCH: return "ESRCH"
        case ECONNREFUSED: return "ECONNREFUSED"
        case ETIMEDOUT: return "ETIMEDOUT"
        case EHOSTUNREACH: return "EHOSTUNREACH"
        case ENETUNREACH: return "ENETUNREACH"
        default: return String(cString: strerror(code))
        }
    }

    // MARK: - S2a File Isolation

    static func runS2aFile(cfg: Config) -> [String: JSONValue] {
        let hostHome = cfg.hostUser.isEmpty ? "/Users/unknown" : "/Users/\(cfg.hostUser)"
        let privateTargets: [(String, String)] = [
            ("host_home", hostHome),
            ("host_documents", "\(hostHome)/Documents"),
            ("host_desktop", "\(hostHome)/Desktop"),
            ("host_downloads", "\(hostHome)/Downloads"),
            ("host_ssh", "\(hostHome)/.ssh"),
            ("host_keychains_dir", "\(hostHome)/Library/Keychains"),
        ]

        var checks: [String: JSONValue] = [:]
        var allPrivateDenied = true
        for (key, path) in privateTargets {
            let res = probeDirectoryRead(path)
            if res["accessible"] == .bool(true) {
                allPrivateDenied = false
            }
            checks[key] = .object(res)
        }

        checks["host_home_stat"] = .object(probeStatMetadata(hostHome))
        checks["host_public"] = .object(probeDirectoryRead("\(hostHome)/Public"))
        checks["users_shared"] = .object(probeDirectoryRead("/Users/Shared"))

        if let peerBoxId = cfg.peerBoxId, let peerId = try? BoxIdentifier(peerBoxId) {
            let peerRes = probeDirectoryRead(peerId.homeDirectory)
            if peerRes["accessible"] == .bool(true) {
                allPrivateDenied = false
            }
            checks["peer_box_home"] = .object(peerRes)
        }

        if let privTmp = cfg.hostTmpPrivateFile {
            let tmpRes = probeFileRead(privTmp)
            if tmpRes["accessible"] == .bool(true) {
                allPrivateDenied = false
            }
            checks["host_tmp_0600"] = .object(tmpRes)
        }

        if let worldTmp = cfg.hostTmpWorldFile {
            checks["host_tmp_0644"] = .object(probeFileRead(worldTmp))
        }

        checks["pass"] = .bool(allPrivateDenied)
        return checks
    }

    // MARK: - S2b Keychain Isolation

    static func runS2bKeychain(cfg: Config) -> [String: JSONValue] {
        let hostHome = cfg.hostUser.isEmpty ? "/Users/unknown" : "/Users/\(cfg.hostUser)"
        let hostLoginKeychain = "\(hostHome)/Library/Keychains/login.keychain-db"

        let listRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/usr/bin/security", arguments: ["list-keychains", "-d", "user"]),
            timeoutSeconds: 4.0
        )
        let listLines = (listRes?.stdout ?? "")
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "\"", with: "") }

        let seesHostKeychainInList = !cfg.hostUser.isEmpty && listLines.contains { $0.contains("/Users/\(cfg.hostUser)/") }
        let directHostRead = probeFileRead(hostLoginKeychain)
        let dumpHostRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/usr/bin/security", arguments: ["dump-keychain", hostLoginKeychain]),
            timeoutSeconds: 4.0
        )
        let dumpHostSucceeded = dumpHostRes?.succeeded ?? false
        let pass = !seesHostKeychainInList && (directHostRead["accessible"] == .bool(false)) && !dumpHostSucceeded

        return [
            "user_keychains": .array(listLines.map { .string($0) }),
            "sees_host_keychain_in_list": .bool(seesHostKeychainInList),
            "host_login_keychain_file_read": .object(directHostRead),
            "host_login_keychain_dump_exit": .int(Int(dumpHostRes?.exitCode ?? -1)),
            "pass": .bool(pass),
        ]
    }

    // MARK: - S2c Clipboard Isolation

    static func runS2cClipboard(cfg: Config) -> [String: JSONValue] {
        let pbpasteRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/usr/bin/pbpaste", arguments: []),
            timeoutSeconds: 3.0
        )
        let stdout = pbpasteRes?.stdout ?? ""
        let stderr = (pbpasteRes?.stderr ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let markerMatched: Bool
        if let marker = cfg.clipboardMarker, !marker.isEmpty {
            markerMatched = stdout.contains(marker)
        } else {
            markerMatched = false
        }

        return [
            "pbpaste_exit_code": .int(Int(pbpasteRes?.exitCode ?? -1)),
            "pbpaste_timed_out": .bool(pbpasteRes?.timedOut ?? true),
            "pbpaste_output_length": .int(stdout.count),
            "pbpaste_stderr": .string(stderr),
            "host_marker_leaked": .bool(markerMatched),
            "pass": .bool(!markerMatched),
        ]
    }

    // MARK: - S2d TCC Isolation

    static func runS2dTcc(cfg: Config) -> [String: JSONValue] {
        let screenCapturePreflight = CGPreflightScreenCaptureAccess()
        let accessibilityTrusted = AXIsProcessTrusted()
        let eventPostPreflight = CGPreflightPostEventAccess()
        let cameraStatus = authStatusName(AVCaptureDevice.authorizationStatus(for: .video))
        let micStatus = authStatusName(AVCaptureDevice.authorizationStatus(for: .audio))
        let contactsStatus = contactsStatusName(CNContactStore.authorizationStatus(for: .contacts))

        // Also test ScreenCaptureKit shareable content query with a short non-blocking timeout
        let sckOutcome = probeScreenCaptureKit()

        let hostAddressBookPath = cfg.hostUser.isEmpty
            ? "/Users/unknown/Library/Application Support/AddressBook"
            : "/Users/\(cfg.hostUser)/Library/Application Support/AddressBook"
        let hostAddressBookRead = probeDirectoryRead(hostAddressBookPath)

        let noInheritedGrant = !screenCapturePreflight
            && !accessibilityTrusted
            && !eventPostPreflight
            && cameraStatus != "authorized"
            && micStatus != "authorized"
            && contactsStatus != "authorized"

        return [
            "screen_capture_preflight_granted": .bool(screenCapturePreflight),
            "screen_capture_kit_probe": .string(sckOutcome),
            "accessibility_trusted": .bool(accessibilityTrusted),
            "cgevent_post_preflight_granted": .bool(eventPostPreflight),
            "camera_auth_status": .string(cameraStatus),
            "microphone_auth_status": .string(micStatus),
            "contacts_auth_status": .string(contactsStatus),
            "host_addressbook_dir": .object(hostAddressBookRead),
            "host_grants_not_inherited": .bool(noInheritedGrant),
        ]
    }

    static func probeScreenCaptureKit() -> String {
        let resultLock = OSAllocatedUnfairLock(initialState: "timeout")
        let sem = DispatchSemaphore(value: 0)
        SCShareableContent.getExcludingDesktopWindows(false, onScreenWindowsOnly: true) { content, error in
            if let error {
                let desc = "denied(\((error as NSError).domain):\((error as NSError).code))"
                resultLock.withLock { $0 = desc }
            } else if let content {
                let desc = "returned(displays=\(content.displays.count),windows=\(content.windows.count))"
                resultLock.withLock { $0 = desc }
            }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 2.5)
        return resultLock.withLock { $0 }
    }

    static func authStatusName(_ s: AVAuthorizationStatus) -> String {
        switch s {
        case .notDetermined: return "not_determined"
        case .restricted: return "restricted"
        case .denied: return "denied"
        case .authorized: return "authorized"
        @unknown default: return "unknown"
        }
    }

    static func contactsStatusName(_ s: CNAuthorizationStatus) -> String {
        switch s {
        case .notDetermined: return "not_determined"
        case .restricted: return "restricted"
        case .denied: return "denied"
        case .authorized: return "authorized"
        @unknown default: return "unknown"
        }
    }

    // MARK: - S2e Process Isolation

    static func runS2eProcess(cfg: Config) -> [String: JSONValue] {
        let psRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/bin/ps", arguments: ["aux"]),
            timeoutSeconds: 4.0
        )
        let lines = (psRes?.stdout ?? "").split(whereSeparator: \.isNewline)
        let seesHostProcs = !cfg.hostUser.isEmpty && lines.contains { $0.hasPrefix("\(cfg.hostUser) ") }

        var procArgsReadable = false
        var procArgsErrno = "not_tested"
        var killZeroAllowed = false
        var killZeroErrno = "not_tested"

        if let hostPid = cfg.hostPid, hostPid > 1 {
            let argsCheck = probeKernProcArgs(pid: hostPid)
            procArgsReadable = argsCheck.readable
            procArgsErrno = argsCheck.error

            if kill(hostPid, 0) == 0 {
                killZeroAllowed = true
                killZeroErrno = "OK"
            } else {
                killZeroAllowed = false
                killZeroErrno = errnoName(errno)
            }
        }

        let pass = !procArgsReadable && !killZeroAllowed
        return [
            "ps_aux_total_lines": .int(lines.count),
            "ps_aux_sees_host_user_processes": .bool(seesHostProcs),
            "host_pid_tested": cfg.hostPid.map { .int(Int($0)) } ?? .null,
            "kern_procargs2_readable": .bool(procArgsReadable),
            "kern_procargs2_error": .string(procArgsErrno),
            "kill_sig0_allowed": .bool(killZeroAllowed),
            "kill_sig0_error": .string(killZeroErrno),
            "pass": .bool(pass),
        ]
    }

    static func probeKernProcArgs(pid: Int32) -> (readable: Bool, error: String) {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        if sysctl(&mib, 3, nil, &size, nil, 0) != 0 || size == 0 {
            return (false, errnoName(errno))
        }
        var buf = [UInt8](repeating: 0, count: size)
        if sysctl(&mib, 3, &buf, &size, nil, 0) != 0 {
            return (false, errnoName(errno))
        }
        return (size > 0, "OK")
    }

    // MARK: - S2f Identity Exposure

    static func runS2fIdentity(cfg: Config) -> [String: JSONValue] {
        let computerNameRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/usr/sbin/scutil", arguments: ["--get", "ComputerName"]),
            timeoutSeconds: 3.0
        )
        let computerNameVisible = (computerNameRes?.succeeded ?? false)
            && !(computerNameRes?.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)

        let hostnameSysctl = readSysctlString("kern.hostname")
        let modelSysctl = readSysctlString("hw.model")

        let iokitDirect = readIOPlatformProperties()
        let ioregRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/usr/sbin/ioreg", arguments: ["-rd1", "-c", "IOPlatformExpertDevice"]),
            timeoutSeconds: 3.0
        )
        let ioregOut = ioregRes?.stdout ?? ""
        let ioregHasSerial = ioregOut.contains("IOPlatformSerialNumber")
        let ioregHasUuid = ioregOut.contains("IOPlatformUUID")

        var dsclRealNameVisible = false
        var dsclRealNameRedacted = "<not_tested>"
        if !cfg.hostUser.isEmpty {
            let dsclRes = try? ProcessRunner.runWithTimeout(
                DsclCommandBuilder.readUser(shortName: cfg.hostUser, key: "RealName"),
                timeoutSeconds: 3.0
            )
            if let out = dsclRes?.stdout, dsclRes?.succeeded == true,
               let parsed = DsclParser.parseSingleAttribute(out, key: "RealName"), !parsed.isEmpty {
                dsclRealNameVisible = true
                dsclRealNameRedacted = SbplBuilder.redactSensitiveValue(parsed)
            }
        }

        let whoRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/usr/bin/who", arguments: []),
            timeoutSeconds: 3.0
        )
        let whoSeesHost = !cfg.hostUser.isEmpty && ((whoRes?.stdout ?? "").contains(cfg.hostUser))

        let lastRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/usr/bin/last", arguments: ["-5"]),
            timeoutSeconds: 3.0
        )
        let lastSeesHost = !cfg.hostUser.isEmpty && ((lastRes?.stdout ?? "").contains(cfg.hostUser))

        let ifconfigRes = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/sbin/ifconfig", arguments: ["en0"]),
            timeoutSeconds: 3.0
        )
        let en0Out = ifconfigRes?.stdout ?? ""
        var macVisible = false
        for line in en0Out.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("ether ") {
                macVisible = true
                break
            }
        }

        return [
            "computer_name_visible": .bool(computerNameVisible),
            "computer_name_redacted": .string(SbplBuilder.redactSensitiveValue(computerNameRes?.stdout)),
            "sysctl_kern_hostname_visible": .bool(hostnameSysctl.visible),
            "sysctl_kern_hostname_error": .string(hostnameSysctl.error),
            "sysctl_kern_hostname_redacted": .string(SbplBuilder.redactSensitiveValue(hostnameSysctl.value)),
            "sysctl_hw_model_visible": .bool(modelSysctl.visible),
            "sysctl_hw_model_redacted": .string(SbplBuilder.redactSensitiveValue(modelSysctl.value)),
            "iokit_serial_visible": .bool(iokitDirect.serial != nil),
            "iokit_serial_redacted": .string(SbplBuilder.redactSensitiveValue(iokitDirect.serial)),
            "iokit_uuid_visible": .bool(iokitDirect.uuid != nil),
            "iokit_uuid_redacted": .string(SbplBuilder.redactSensitiveValue(iokitDirect.uuid)),
            "ioreg_serial_visible": .bool(ioregHasSerial),
            "ioreg_uuid_visible": .bool(ioregHasUuid),
            "dscl_host_realname_visible": .bool(dsclRealNameVisible),
            "dscl_host_realname_redacted": .string(dsclRealNameRedacted),
            "who_sees_host_user": .bool(whoSeesHost),
            "last_sees_host_user": .bool(lastSeesHost),
            "en0_mac_visible": .bool(macVisible),
        ]
    }

    static func readSysctlString(_ name: String) -> (visible: Bool, value: String?, error: String) {
        var size: Int = 0
        if sysctlbyname(name, nil, &size, nil, 0) != 0 {
            return (false, nil, errnoName(errno))
        }
        guard size > 0 else {
            return (false, nil, "empty")
        }
        var buf = [UInt8](repeating: 0, count: size + 1)
        if sysctlbyname(name, &buf, &size, nil, 0) != 0 {
            return (false, nil, errnoName(errno))
        }
        let val = String(decoding: buf.prefix { $0 != 0 }, as: UTF8.self)
        return (!val.isEmpty, val, "OK")
    }

    static func readIOPlatformProperties() -> (serial: String?, uuid: String?) {
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard entry != IO_OBJECT_NULL else {
            return (nil, nil)
        }
        defer { IOObjectRelease(entry) }
        let serial = IORegistryEntryCreateCFProperty(
            entry,
            "IOPlatformSerialNumber" as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String
        let uuid = IORegistryEntryCreateCFProperty(
            entry,
            "IOPlatformUUID" as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String
        return (serial, uuid)
    }

    // MARK: - S2g Network Reachability

    static func runS2gNetwork(cfg: Config) -> [String: JSONValue] {
        let publicTcp = probeTcpIPv4(host: "1.1.1.1", port: 443, timeoutMs: 2500)
        let gatewayIp = detectDefaultGatewayIPv4()
        let gatewayProbe: [String: JSONValue]
        if let gw = gatewayIp {
            gatewayProbe = probeTcpIPv4(host: gw, port: 80, timeoutMs: 1500)
        } else {
            gatewayProbe = ["reachable": .bool(false), "detail": .string("no_default_gateway")]
        }

        let loopbackProbe: [String: JSONValue]
        if let port = cfg.hostLoopbackPort {
            loopbackProbe = probeTcpIPv4(host: "127.0.0.1", port: port, timeoutMs: 1500)
        } else {
            loopbackProbe = ["reachable": .bool(false), "detail": .string("not_configured")]
        }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var resPtr: UnsafeMutablePointer<addrinfo>?
        let gaiCode = getaddrinfo("example.com", "443", &hints, &resPtr)
        if let resPtr { freeaddrinfo(resPtr) }

        return [
            "public_1_1_1_1_443": .object(publicTcp),
            "lan_gateway_redacted": .string(SbplBuilder.redactSensitiveValue(gatewayIp)),
            "lan_gateway_tcp_80": .object(gatewayProbe),
            "host_loopback_127_0_0_1": .object(loopbackProbe),
            "dns_example_com_ok": .bool(gaiCode == 0),
            "policy_status": .string("unforced_until_s3_network_extension"),
        ]
    }

    static func detectDefaultGatewayIPv4() -> String? {
        guard let res = try? ProcessRunner.runWithTimeout(
            CommandSpec(executable: "/sbin/route", arguments: ["-n", "get", "default"]),
            timeoutSeconds: 2.5
        ), res.succeeded else {
            return nil
        }
        for line in res.stdout.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("gateway:") {
                let ip = String(trimmed.dropFirst("gateway:".count)).trimmingCharacters(in: .whitespaces)
                if ip.contains(".") { return ip }
            }
        }
        return nil
    }

    static func probeTcpIPv4(host: String, port: UInt16, timeoutMs: Int32) -> [String: JSONValue] {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            return ["connected": .bool(false), "error": .string(errnoName(errno))]
        }
        defer { close(fd) }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else {
            return ["connected": .bool(false), "error": .string("invalid_ipv4")]
        }

        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc == 0 {
            return ["connected": .bool(true), "l3_reachable": .bool(true), "error": .string("OK")]
        }
        if errno != EINPROGRESS {
            let e = errno
            return [
                "connected": .bool(false),
                "l3_reachable": .bool(e == ECONNREFUSED),
                "error": .string(errnoName(e)),
            ]
        }

        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let prc = poll(&pfd, 1, timeoutMs)
        if prc <= 0 {
            return ["connected": .bool(false), "l3_reachable": .bool(false), "error": .string("ETIMEDOUT")]
        }
        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len)
        if soError == 0 {
            return ["connected": .bool(true), "l3_reachable": .bool(true), "error": .string("OK")]
        }
        return [
            "connected": .bool(false),
            "l3_reachable": .bool(soError == ECONNREFUSED),
            "error": .string(errnoName(soError)),
        ]
    }

    // MARK: - S2h Cross-Box Isolation

    static func runS2hCrossBox(cfg: Config) -> [String: JSONValue] {
        guard let rawPeer = cfg.peerBoxId, let peerId = try? BoxIdentifier(rawPeer) else {
            return ["configured": .bool(false), "pass": .bool(false)]
        }

        let homeCheck = probeDirectoryRead(peerId.homeDirectory)
        let socketConnect = probeUnixSocketConnect(path: peerId.socketPath)

        var peerKillAllowed = false
        var peerKillError = "not_tested"
        var peerArgsReadable = false
        if let peerPid = cfg.peerPid, peerPid > 1 {
            if kill(peerPid, 0) == 0 {
                peerKillAllowed = true
                peerKillError = "OK"
            } else {
                peerKillAllowed = false
                peerKillError = errnoName(errno)
            }
            peerArgsReadable = probeKernProcArgs(pid: peerPid).readable
        }

        let pass = (homeCheck["accessible"] == .bool(false))
            && (socketConnect["connected"] == .bool(false))
            && !peerKillAllowed
            && !peerArgsReadable

        return [
            "peer_box_id": .string(peerId.boxId),
            "peer_home": .object(homeCheck),
            "peer_agent_socket": .object(socketConnect),
            "peer_pid": cfg.peerPid.map { .int(Int($0)) } ?? .null,
            "peer_kill_sig0_allowed": .bool(peerKillAllowed),
            "peer_kill_sig0_error": .string(peerKillError),
            "peer_kern_procargs2_readable": .bool(peerArgsReadable),
            "pass": .bool(pass),
        ]
    }

    static func probeUnixSocketConnect(path: String) -> [String: JSONValue] {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            return ["connected": .bool(false), "error": .string(errnoName(errno))]
        }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let utf8 = Array(path.utf8CString)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard utf8.count <= maxLen else {
            return ["connected": .bool(false), "error": .string("path_too_long")]
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuf in
            for i in 0..<utf8.count {
                rawBuf[i] = UInt8(bitPattern: utf8[i])
            }
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc == 0 {
            return ["connected": .bool(true), "error": .string("OK")]
        }
        let err = errno
        return [
            "connected": .bool(false),
            "errno": .int(Int(err)),
            "error": .string(errnoName(err)),
        ]
    }
}
