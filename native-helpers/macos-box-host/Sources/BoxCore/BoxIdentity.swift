import Foundation

public enum BoxConstants {
    public static let userPrefix = "atombox_"
    public static let primaryGroupName = "atombox"
    public static let controlGroupName = "atombox_ctl"
    public static let commentPrefix = "atomium-box:"
    public static let userShell = "/usr/bin/false"
    public static let secretDirectory = "/var/db/atomium-proto"
    public static let runtimeDirectory = "/private/var/atomium-proto/boxes"
    public static let minGid: UInt32 = 700
    public static let minUid: UInt32 = 701
    public static let evidenceSchema = "atomium-s1-evidence-v1"
}

public enum BoxValidationError: Error, Equatable, CustomStringConvertible, Sendable {
    case invalidBoxId(String)
    case invalidShortNamePrefix(String)
    case missingCommentMarker(shortName: String)
    case invalidCommentMarker(shortName: String, expected: String, actual: String)
    case missingLoginwindowPid
    case invalidPath(String)

    public var description: String {
        switch self {
        case .invalidBoxId(let raw):
            return "Invalid box_id '\(raw)': must match ^[a-z0-9]{2,16}$"
        case .invalidShortNamePrefix(let shortName):
            return "Account '\(shortName)' does not start with required prefix '\(BoxConstants.userPrefix)'"
        case .missingCommentMarker(let shortName):
            return "Account '\(shortName)' is missing required Comment marker '\(BoxConstants.commentPrefix)<box_id>'"
        case .invalidCommentMarker(let shortName, let expected, let actual):
            return "Account '\(shortName)' Comment marker mismatch: expected '\(expected)', got '\(actual)'"
        case .missingLoginwindowPid:
            return "Launch variant V4 requires a valid console loginwindow PID"
        case .invalidPath(let path):
            return "Invalid path: '\(path)'"
        }
    }
}

public struct BoxIdentifier: Equatable, Hashable, Codable, Sendable {
    public let boxId: String

    public init(_ raw: String) throws(BoxValidationError) {
        guard Self.isValidBoxId(raw) else {
            throw .invalidBoxId(raw)
        }
        self.boxId = raw
    }

    public static func isValidBoxId(_ value: String) -> Bool {
        let scalars = value.unicodeScalars
        guard scalars.count >= 2 && scalars.count <= 16 else {
            return false
        }
        return scalars.allSatisfy { scalar in
            (scalar >= "a" && scalar <= "z") || (scalar >= "0" && scalar <= "9")
        }
    }

    public static func fromShortName(_ shortName: String) throws(BoxValidationError) -> BoxIdentifier {
        guard shortName.hasPrefix(BoxConstants.userPrefix) else {
            throw .invalidShortNamePrefix(shortName)
        }
        let suffix = String(shortName.dropFirst(BoxConstants.userPrefix.count))
        return try BoxIdentifier(suffix)
    }

    public var shortName: String {
        "\(BoxConstants.userPrefix)\(boxId)"
    }

    public var commentMarker: String {
        "\(BoxConstants.commentPrefix)\(boxId)"
    }

    public var realName: String {
        "Atomium Box \(boxId)"
    }

    public var homeDirectory: String {
        "/Users/\(shortName)"
    }

    public var tmpDirectory: String {
        "\(homeDirectory)/.tmp"
    }

    public var inboxDirectory: String {
        "\(homeDirectory)/Inbox"
    }

    public var applicationsDirectory: String {
        "\(homeDirectory)/Applications"
    }

    public var secretPath: String {
        "\(BoxConstants.secretDirectory)/\(boxId).secret"
    }

    public var socketDirectory: String {
        "\(BoxConstants.runtimeDirectory)/\(boxId)"
    }

    public var socketPath: String {
        "\(socketDirectory)/agent.sock"
    }
}

public enum BoxAccountGuard {
    /// Validates that an account satisfies BOTH safety guardrails from spec §3.2:
    /// 1. Short name starts with `atombox_` with a valid `box_id` suffix.
    /// 2. Directory Services `Comment` attribute equals `atomium-box:<box_id>`.
    public static func validateManagedAccount(
        shortName: String,
        comment: String?
    ) throws(BoxValidationError) -> BoxIdentifier {
        let identifier = try BoxIdentifier.fromShortName(shortName)
        guard let rawComment = comment else {
            throw .missingCommentMarker(shortName: shortName)
        }
        let trimmed = rawComment.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed == identifier.commentMarker else {
            throw .invalidCommentMarker(
                shortName: shortName,
                expected: identifier.commentMarker,
                actual: trimmed
            )
        }
        return identifier
    }

    /// Redacts an email address per spec §3.5: first 2 characters + `***`.
    public static func redactEmail(_ email: String) -> String {
        let trimmed = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return "***"
        }
        let localPart = trimmed.split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? trimmed
        let prefix = String(localPart.prefix(2))
        return "\(prefix)***"
    }
}
