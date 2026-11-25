import BoxCore
import Darwin
import Foundation

struct PreparedAppReport: Codable {
    let boxId: String
    let sourcePath: String
    let destinationPath: String
    let bundleId: String
    let version: String
    let teamId: String
    let codesignOk: Bool
    let codesignDetail: String
    let spctlOk: Bool
    let spctlDetail: String

    enum CodingKeys: String, CodingKey {
        case boxId = "box_id"
        case sourcePath = "source_path"
        case destinationPath = "destination_path"
        case bundleId = "bundle_id"
        case version
        case teamId = "team_id"
        case codesignOk = "codesign_ok"
        case codesignDetail = "codesign_detail"
        case spctlOk = "spctl_ok"
        case spctlDetail = "spctl_detail"
    }
}

struct LaunchAttemptReport: Codable {
    let boxId: String
    let uid: UInt32
    let variant: String
    let appPath: String
    let executablePath: String
    let workingDirectory: String
    let tmpDirectory: String
    let command: String
    let sbplProfile: String?
    let loginwindowPid: Int32?
    let exitedEarly: Bool
    let exitCode: Int32?
    let stdoutLogPath: String
    let stderrLogPath: String
    let stderrSummary: String
    let stdoutSummary: String
    let psOutput: String
    let launchctlSummary: String
    let guiDomainSummary: String

    enum CodingKeys: String, CodingKey {
        case boxId = "box_id"
        case uid
        case variant
        case appPath = "app_path"
        case executablePath = "executable_path"
        case workingDirectory = "working_directory"
        case tmpDirectory = "tmp_directory"
        case command
        case sbplProfile = "sbpl_profile"
        case loginwindowPid = "loginwindow_pid"
        case exitedEarly = "exited_early"
        case exitCode = "exit_code"
        case stdoutLogPath = "stdout_log_path"
        case stderrLogPath = "stderr_log_path"
        case stderrSummary = "stderr_summary"
        case stdoutSummary = "stdout_summary"
        case psOutput = "ps_output"
        case launchctlSummary = "launchctl_summary"
        case guiDomainSummary = "gui_domain_summary"
    }
}

enum BoxLauncher {
    static func resolveManagedBox(_ rawBoxId: String) throws -> (BoxIdentifier, UInt32, UInt32) {
        let identifier = try BoxIdentifier(rawBoxId)
        let record = BoxLifecycle.inspectAccount(shortName: identifier.shortName)
        guard record.managed else {
            throw BoxCLIError.guardrailRejected(record.validationError ?? "Account \(identifier.shortName) is not a managed Atomium Box")
        }
        guard let uid = record.uid, let gid = record.primaryGid else {
            throw BoxCLIError.notFound("Box user \(identifier.shortName) missing UID/GID")
        }
        return (identifier, uid, gid)
    }

    static func resolveBundleExecutable(appPath: String) throws -> String {
        let infoPlistPath = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = FileManager.default.contents(atPath: infoPlistPath),
              let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let exeName = plist["CFBundleExecutable"] as? String,
              !exeName.isEmpty else {
            throw BoxCLIError.invalidArguments("Could not read CFBundleExecutable from \(infoPlistPath)")
        }
        let exePath = (appPath as NSString).appendingPathComponent("Contents/MacOS/\(exeName)")
        guard FileManager.default.isExecutableFile(atPath: exePath) else {
            throw BoxCLIError.notFound("App executable not found or not executable: \(exePath)")
        }
        return exePath
    }

    static func readBundleMetadata(appPath: String) -> (bundleId: String, version: String) {
        let infoPlistPath = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = FileManager.default.contents(atPath: infoPlistPath),
              let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else {
            return ("unknown", "unknown")
        }
        let bundleId = (plist["CFBundleIdentifier"] as? String) ?? "unknown"
        let version = (plist["CFBundleShortVersionString"] as? String)
            ?? (plist["CFBundleVersion"] as? String)
            ?? "unknown"
        return (bundleId, version)
    }

    static func extractTeamId(appPath: String) -> String {
        guard let res = try? ProcessRunner.run(
            CommandSpec(executable: "/usr/bin/codesign", arguments: ["-dv", "--verbose=2", appPath])
        ) else {
            return "unknown"
        }
        let combined = res.stdout + "\n" + res.stderr
        for line in combined.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("TeamIdentifier=") {
                return String(line.dropFirst("TeamIdentifier=".count)).trimmingCharacters(in: .whitespaces)
            }
        }
        return "not set"
    }

    static func prepareApp(boxId rawBoxId: String, sourceAppPath: String, stripQuarantine: Bool) throws -> PreparedAppReport {
        try BoxLifecycle.requireRoot(for: "prepare-app")
        let (identifier, uid, gid) = try resolveManagedBox(rawBoxId)

        guard sourceAppPath.hasSuffix(".app"), FileManager.default.fileExists(atPath: sourceAppPath) else {
            throw BoxCLIError.notFound("Source app bundle does not exist: \(sourceAppPath)")
        }

        let appName = (sourceAppPath as NSString).lastPathComponent
        let destPath = (identifier.applicationsDirectory as NSString).appendingPathComponent(appName)

        let fm = FileManager.default
        if !fm.fileExists(atPath: identifier.applicationsDirectory) {
            try fm.createDirectory(atPath: identifier.applicationsDirectory, withIntermediateDirectories: true)
            try BoxLifecycle.setOwnerAndMode(path: identifier.applicationsDirectory, uid: uid, gid: gid, mode: 0o700)
        }
        if fm.fileExists(atPath: destPath) {
            try fm.removeItem(atPath: destPath)
        }

        let dittoRes = try ProcessRunner.run(
            CommandSpec(executable: "/usr/bin/ditto", arguments: [sourceAppPath, destPath])
        )
        guard dittoRes.succeeded else {
            throw BoxCLIError.commandFailed("ditto \(sourceAppPath) \(destPath)", dittoRes.stderr)
        }

        let chownRes = try ProcessRunner.run(
            CommandSpec(executable: "/usr/sbin/chown", arguments: ["-R", "\(uid):\(gid)", destPath])
        )
        guard chownRes.succeeded else {
            throw BoxCLIError.commandFailed("chown -R \(uid):\(gid) \(destPath)", chownRes.stderr)
        }

        if stripQuarantine {
            _ = try? ProcessRunner.run(
                CommandSpec(executable: "/usr/bin/xattr", arguments: ["-dr", "com.apple.quarantine", destPath])
            )
        }

        let codesignRes = try ProcessRunner.run(
            CommandSpec(executable: "/usr/bin/codesign", arguments: ["--verify", "--deep", "--strict", destPath])
        )
        let spctlRes = try ProcessRunner.run(
            CommandSpec(executable: "/usr/sbin/spctl", arguments: ["-a", "-vv", destPath])
        )
        let meta = readBundleMetadata(appPath: destPath)
        let teamId = extractTeamId(appPath: destPath)

        return PreparedAppReport(
            boxId: identifier.boxId,
            sourcePath: sourceAppPath,
            destinationPath: destPath,
            bundleId: meta.bundleId,
            version: meta.version,
            teamId: teamId,
            codesignOk: codesignRes.succeeded,
            codesignDetail: (codesignRes.stdout + codesignRes.stderr).trimmingCharacters(in: .whitespacesAndNewlines),
            spctlOk: spctlRes.succeeded,
            spctlDetail: (spctlRes.stdout + spctlRes.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    static func findConsoleLoginwindowPid() -> Int32? {
        if let res = try? ProcessRunner.run(CommandSpec(executable: "/usr/bin/pgrep", arguments: ["-x", "loginwindow"])),
           res.succeeded {
            for line in res.stdout.split(whereSeparator: \.isNewline) {
                if let pid = Int32(line.trimmingCharacters(in: .whitespaces)), pid > 0 {
                    return pid
                }
            }
        }
        return nil
    }

    static func summarizeLaunchctl(uid: UInt32) -> String {
        guard let res = try? ProcessRunner.run(LaunchctlCommandBuilder.printUserDomain(uid: uid)) else {
            return "failed to invoke launchctl print user/\(uid)"
        }
        if !res.succeeded {
            let err = res.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            return "exit=\(res.exitCode): \(err)"
        }
        let lines = res.stdout.split(whereSeparator: \.isNewline).map(String.init)
        let interesting = lines.prefix(20).joined(separator: "\n")
        return interesting
    }

    static func summarizeGuiDomain(uid: UInt32) -> String {
        let cmd = CommandSpec(executable: "/bin/launchctl", arguments: ["print", "gui/\(uid)"])
        guard let res = try? ProcessRunner.run(cmd) else {
            return "failed to invoke launchctl print gui/\(uid)"
        }
        if !res.succeeded {
            let err = (res.stderr + "\n" + res.stdout).trimmingCharacters(in: .whitespacesAndNewlines)
            return "exit=\(res.exitCode): \(err)"
        }
        let lines = res.stdout.split(whereSeparator: \.isNewline).map(String.init)
        return lines.prefix(15).joined(separator: "\n")
    }

    static func capturePsForUid(_ uid: UInt32) -> String {
        guard let res = try? ProcessRunner.run(
            CommandSpec(executable: "/bin/ps", arguments: ["-o", "user,pid,ppid,command", "-u", String(uid)])
        ) else {
            return ""
        }
        return res.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func prepareBoxRuntimeEnvironment(identifier: BoxIdentifier, uid: UInt32, gid: UInt32) throws -> [String: String] {
        let fm = FileManager.default
        if !fm.fileExists(atPath: identifier.tmpDirectory) {
            try fm.createDirectory(atPath: identifier.tmpDirectory, withIntermediateDirectories: true)
        }
        try BoxLifecycle.setOwnerAndMode(path: identifier.tmpDirectory, uid: uid, gid: gid, mode: 0o700)

        var env = ProcessInfo.processInfo.environment
        for hostKey in [
            "__CF_USER_TEXT_ENCODING",
            "PWD",
            "OLDPWD",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "SUDO_COMMAND",
            "SUDO_USER",
            "SUDO_UID",
            "SUDO_GID",
        ] {
            env.removeValue(forKey: hostKey)
        }
        env["HOME"] = identifier.homeDirectory
        env["TMPDIR"] = identifier.tmpDirectory
        env["USER"] = identifier.shortName
        env["LOGNAME"] = identifier.shortName
        env["SHELL"] = "/bin/zsh"
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        return env
    }

    static func createOwnedLogFile(atPath path: String, uid: UInt32, gid: UInt32) throws {
        try Data().write(to: URL(fileURLWithPath: path), options: .atomic)
        try BoxLifecycle.setOwnerAndMode(path: path, uid: uid, gid: gid, mode: 0o600)
    }

    static func readNonBlockingLogSummary(atPath path: String, maxChars: Int = 4000) -> String {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)), !data.isEmpty else {
            return ""
        }
        let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        if text.count <= maxChars {
            return text
        }
        return String(text.prefix(maxChars)) + "\n...(truncated, total \(text.count) chars)"
    }

    static func launch(
        boxId rawBoxId: String,
        appPath: String,
        variant: LaunchVariant,
        waitSeconds: Double,
        sbplProfile: String?,
        extraArgs: [String]
    ) throws -> LaunchAttemptReport {
        try BoxLifecycle.requireRoot(for: "launch")
        let (identifier, uid, gid) = try resolveManagedBox(rawBoxId)
        let exePath = try resolveBundleExecutable(appPath: appPath)
        let env = try prepareBoxRuntimeEnvironment(identifier: identifier, uid: uid, gid: gid)

        let loginwindowPid: Int32? = (variant == .v4) ? findConsoleLoginwindowPid() : nil

        let effectiveExe: String
        let effectiveArgs: [String]
        if let sbplProfile {
            if variant == .v3 {
                throw BoxCLIError.invalidArguments("--sbpl cannot be combined with V3 (open -a); use V1, V2, or V4")
            }
            effectiveExe = "/usr/bin/sandbox-exec"
            effectiveArgs = ["-f", sbplProfile, exePath] + extraArgs
        } else {
            effectiveExe = exePath
            effectiveArgs = extraArgs
        }

        let stamp = Int(Date().timeIntervalSince1970 * 1000)
        let prefix = "\(identifier.tmpDirectory)/launch-\(variant.rawValue.lowercased())-\(stamp)"
        let stdoutLogPath = "\(prefix).stdout.log"
        let stderrLogPath = "\(prefix).stderr.log"
        try createOwnedLogFile(atPath: stdoutLogPath, uid: uid, gid: gid)
        try createOwnedLogFile(atPath: stderrLogPath, uid: uid, gid: gid)

        let openWrapperStdoutPath = (variant == .v3) ? "\(prefix).open-stdout.log" : nil
        let openWrapperStderrPath = (variant == .v3) ? "\(prefix).open-stderr.log" : nil
        if let openWrapperStdoutPath, let openWrapperStderrPath {
            try createOwnedLogFile(atPath: openWrapperStdoutPath, uid: uid, gid: gid)
            try createOwnedLogFile(atPath: openWrapperStderrPath, uid: uid, gid: gid)
        }

        let spec = try LaunchctlCommandBuilder.buildLaunchCommand(
            variant: variant,
            id: identifier,
            uid: uid,
            appPath: appPath,
            executablePath: effectiveExe,
            loginwindowPid: loginwindowPid,
            stdoutPath: (variant == .v3) ? stdoutLogPath : nil,
            stderrPath: (variant == .v3) ? stderrLogPath : nil,
            arguments: effectiveArgs
        )

        let process = Process()
        process.executableURL = URL(fileURLWithPath: spec.executable)
        process.arguments = spec.arguments
        process.currentDirectoryURL = URL(fileURLWithPath: identifier.homeDirectory, isDirectory: true)
        process.environment = env

        let procOutPath = openWrapperStdoutPath ?? stdoutLogPath
        let procErrPath = openWrapperStderrPath ?? stderrLogPath
        guard let stdoutHandle = FileHandle(forWritingAtPath: procOutPath),
              let stderrHandle = FileHandle(forWritingAtPath: procErrPath) else {
            throw BoxCLIError.internalError("Failed to open launch log files in \(identifier.tmpDirectory)")
        }
        process.standardOutput = stdoutHandle
        process.standardError = stderrHandle

        try process.run()
        try? stdoutHandle.close()
        try? stderrHandle.close()

        let deadline = Date().addingTimeInterval(max(0.5, waitSeconds))
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        // For V3 (`open -a`), `open` returns 0 as soon as LaunchServices spawns the app;
        // wait the remaining window so startup stderr/stdout and `ps` reflect the launched app.
        if variant == .v3 && !process.isRunning && process.terminationStatus == 0 {
            while Date() < deadline {
                Thread.sleep(forTimeInterval: 0.1)
            }
        }

        let exitedEarly: Bool
        let exitCode: Int32?
        if variant == .v3 {
            let wrapperFailed = !process.isRunning && process.terminationStatus != 0
            exitedEarly = wrapperFailed
            exitCode = !process.isRunning ? process.terminationStatus : nil
        } else {
            exitedEarly = !process.isRunning
            exitCode = exitedEarly ? process.terminationStatus : nil
        }

        var stdoutParts: [String] = []
        var stderrParts: [String] = []
        if let openWrapperStdoutPath {
            let s = readNonBlockingLogSummary(atPath: openWrapperStdoutPath)
            if !s.isEmpty { stdoutParts.append("[open] \(s)") }
        }
        if let openWrapperStderrPath {
            let s = readNonBlockingLogSummary(atPath: openWrapperStderrPath)
            if !s.isEmpty { stderrParts.append("[open] \(s)") }
        }
        let appOut = readNonBlockingLogSummary(atPath: stdoutLogPath)
        if !appOut.isEmpty { stdoutParts.append(appOut) }
        let appErr = readNonBlockingLogSummary(atPath: stderrLogPath)
        if !appErr.isEmpty { stderrParts.append(appErr) }

        let stdoutSummary = stdoutParts.joined(separator: "\n")
        let stderrSummary = stderrParts.joined(separator: "\n")
        let psOutput = capturePsForUid(uid)
        let launchctlSummary = summarizeLaunchctl(uid: uid)
        let guiDomainSummary = summarizeGuiDomain(uid: uid)

        return LaunchAttemptReport(
            boxId: identifier.boxId,
            uid: uid,
            variant: variant.rawValue,
            appPath: appPath,
            executablePath: exePath,
            workingDirectory: identifier.homeDirectory,
            tmpDirectory: identifier.tmpDirectory,
            command: spec.displayShellCommand,
            sbplProfile: sbplProfile,
            loginwindowPid: loginwindowPid,
            exitedEarly: exitedEarly,
            exitCode: exitCode,
            stdoutLogPath: stdoutLogPath,
            stderrLogPath: stderrLogPath,
            stderrSummary: stderrSummary,
            stdoutSummary: stdoutSummary,
            psOutput: psOutput,
            launchctlSummary: launchctlSummary,
            guiDomainSummary: guiDomainSummary
        )
    }

    static func execCommand(
        boxId rawBoxId: String,
        useAsuser: Bool,
        command: [String]
    ) throws -> Int32 {
        try BoxLifecycle.requireRoot(for: "exec")
        guard !command.isEmpty else {
            throw BoxCLIError.invalidArguments("exec requires a command after --")
        }
        let (identifier, uid, gid) = try resolveManagedBox(rawBoxId)
        let env = try prepareBoxRuntimeEnvironment(identifier: identifier, uid: uid, gid: gid)
        let envPrefix = LaunchctlCommandBuilder.boxEnvironmentPrefix(id: identifier)

        let spec: CommandSpec
        if useAsuser {
            spec = CommandSpec(
                executable: "/bin/launchctl",
                arguments: ["asuser", String(uid), "/usr/bin/sudo", "-u", identifier.shortName, "-H"] + envPrefix + command
            )
        } else {
            spec = CommandSpec(
                executable: "/usr/bin/sudo",
                arguments: ["-u", identifier.shortName, "-H"] + envPrefix + command
            )
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: spec.executable)
        process.arguments = spec.arguments
        process.currentDirectoryURL = URL(fileURLWithPath: identifier.homeDirectory, isDirectory: true)
        process.environment = env
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}
