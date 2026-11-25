import Foundation

public struct CommandSpec: Equatable, Sendable {
    public let executable: String
    public let arguments: [String]
    /// Optional redacted copy of arguments for display/logging (e.g. passwords).
    public let redactedArguments: [String]?

    public init(executable: String, arguments: [String], redactedArguments: [String]? = nil) {
        self.executable = executable
        self.arguments = arguments
        self.redactedArguments = redactedArguments
    }

    public var argv: [String] {
        [executable] + arguments
    }

    public var displayArgv: [String] {
        [executable] + (redactedArguments ?? arguments)
    }

    public var shellCommand: String {
        argv.map(Self.shellQuote).joined(separator: " ")
    }

    public var displayShellCommand: String {
        displayArgv.map(Self.shellQuote).joined(separator: " ")
    }

    public static func shellQuote(_ token: String) -> String {
        if token.isEmpty {
            return "''"
        }
        let safe = token.unicodeScalars.allSatisfy { scalar in
            (scalar >= "a" && scalar <= "z") ||
            (scalar >= "A" && scalar <= "Z") ||
            (scalar >= "0" && scalar <= "9") ||
            scalar == "_" || scalar == "-" || scalar == "." ||
            scalar == "/" || scalar == ":" || scalar == "=" || scalar == "@"
        }
        if safe {
            return token
        }
        let escaped = token.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }
}

public enum LaunchVariant: String, Codable, CaseIterable, Sendable {
    case v1 = "V1"
    case v2 = "V2"
    case v3 = "V3"
    case v4 = "V4"
}

public enum DsclCommandBuilder {
    public static func listUsers() -> CommandSpec {
        CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-list", "/Users"])
    }

    public static func listUserUniqueIds() -> CommandSpec {
        CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-list", "/Users", "UniqueID"])
    }

    public static func listGroupIds() -> CommandSpec {
        CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-list", "/Groups", "PrimaryGroupID"])
    }

    public static func readUser(shortName: String, key: String? = nil) -> CommandSpec {
        var args = [".", "-read", "/Users/\(shortName)"]
        if let key {
            args.append(key)
        }
        return CommandSpec(executable: "/usr/bin/dscl", arguments: args)
    }

    public static func readGroup(groupName: String, key: String? = nil) -> CommandSpec {
        var args = [".", "-read", "/Groups/\(groupName)"]
        if let key {
            args.append(key)
        }
        return CommandSpec(executable: "/usr/bin/dscl", arguments: args)
    }

    public static func createGroup(groupName: String, gid: UInt32) -> CommandSpec {
        CommandSpec(
            executable: "/usr/sbin/dseditgroup",
            arguments: ["-o", "create", "-i", String(gid), groupName]
        )
    }

    public static func deleteGroup(groupName: String) -> CommandSpec {
        CommandSpec(
            executable: "/usr/sbin/dseditgroup",
            arguments: ["-o", "delete", groupName]
        )
    }

    public static func addUserToGroup(userName: String, groupName: String) -> CommandSpec {
        CommandSpec(
            executable: "/usr/sbin/dseditgroup",
            arguments: ["-o", "edit", "-a", userName, "-t", "user", groupName]
        )
    }

    public static func createUserCommands(
        id: BoxIdentifier,
        uid: UInt32,
        primaryGid: UInt32
    ) -> [CommandSpec] {
        let userPath = "/Users/\(id.shortName)"
        return [
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath]),
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath, "UniqueID", String(uid)]),
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath, "PrimaryGroupID", String(primaryGid)]),
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath, "UserShell", BoxConstants.userShell]),
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath, "NFSHomeDirectory", id.homeDirectory]),
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath, "RealName", id.realName]),
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath, "IsHidden", "1"]),
            CommandSpec(executable: "/usr/bin/dscl", arguments: [".", "-create", userPath, "Comment", id.commentMarker]),
        ]
    }

    public static func setPassword(id: BoxIdentifier, password: String) -> CommandSpec {
        let userPath = "/Users/\(id.shortName)"
        return CommandSpec(
            executable: "/usr/bin/dscl",
            arguments: [".", "-passwd", userPath, password],
            redactedArguments: [".", "-passwd", userPath, "<REDACTED>"]
        )
    }

    public static func createHomeDirectory(id: BoxIdentifier) -> CommandSpec {
        CommandSpec(
            executable: "/usr/sbin/createhomedir",
            arguments: ["-c", "-u", id.shortName]
        )
    }

    public static func deleteUser(id: BoxIdentifier) -> CommandSpec {
        CommandSpec(
            executable: "/usr/bin/dscl",
            arguments: [".", "-delete", "/Users/\(id.shortName)"]
        )
    }
}

public enum LaunchctlCommandBuilder {
    public static func printUserDomain(uid: UInt32) -> CommandSpec {
        CommandSpec(executable: "/bin/launchctl", arguments: ["print", "user/\(uid)"])
    }

    public static func bootstrapUserDomain(uid: UInt32) -> CommandSpec {
        CommandSpec(executable: "/bin/launchctl", arguments: ["bootstrap", "user/\(uid)"])
    }

    public static func boxEnvironmentPrefix(id: BoxIdentifier) -> [String] {
        [
            "/usr/bin/env",
            "HOME=\(id.homeDirectory)",
            "TMPDIR=\(id.tmpDirectory)",
            "USER=\(id.shortName)",
            "LOGNAME=\(id.shortName)",
        ]
    }

    public static func buildLaunchCommand(
        variant: LaunchVariant,
        id: BoxIdentifier,
        uid: UInt32,
        appPath: String,
        executablePath: String,
        loginwindowPid: Int32? = nil,
        stdoutPath: String? = nil,
        stderrPath: String? = nil,
        arguments: [String] = []
    ) throws(BoxValidationError) -> CommandSpec {
        let envPrefix = boxEnvironmentPrefix(id: id)
        switch variant {
        case .v1:
            return CommandSpec(
                executable: "/usr/bin/sudo",
                arguments: ["-u", id.shortName, "-H"] + envPrefix + [executablePath] + arguments
            )
        case .v2:
            return CommandSpec(
                executable: "/usr/bin/sudo",
                arguments: ["/bin/launchctl", "asuser", String(uid), "/usr/bin/sudo", "-u", id.shortName, "-H"] + envPrefix + [executablePath] + arguments
            )
        case .v3:
            var args = ["/bin/launchctl", "asuser", String(uid), "/usr/bin/sudo", "-u", id.shortName, "-H"] + envPrefix + [
                "/usr/bin/open",
                "-n",
                "--env", "HOME=\(id.homeDirectory)",
                "--env", "TMPDIR=\(id.tmpDirectory)",
            ]
            if let stdoutPath {
                args += ["--stdout", stdoutPath]
            }
            if let stderrPath {
                args += ["--stderr", stderrPath]
            }
            args += ["-a", appPath]
            if !arguments.isEmpty {
                args.append("--args")
                args.append(contentsOf: arguments)
            }
            return CommandSpec(executable: "/usr/bin/sudo", arguments: args)
        case .v4:
            guard let pid = loginwindowPid, pid > 0 else {
                throw .missingLoginwindowPid
            }
            return CommandSpec(
                executable: "/usr/bin/sudo",
                arguments: ["/bin/launchctl", "bsexec", String(pid), "/usr/bin/sudo", "-u", id.shortName, "-H"] + envPrefix + [executablePath] + arguments
            )
        }
    }
}
