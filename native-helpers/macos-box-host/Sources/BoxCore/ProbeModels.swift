import Foundation

public enum SbplBuilder {
    /// Generates the §4.9 targeted identity-hardening SBPL profile for a given host short name.
    public static func identityPatchProfile(hostShortName: String, useRegistryClassFallback: Bool = false) throws(BoxValidationError) -> String {
        guard !hostShortName.isEmpty,
              !hostShortName.contains("/"),
              !hostShortName.contains("\""),
              !hostShortName.contains("\\") else {
            throw .invalidPath(hostShortName)
        }
        let iokitRule: String
        if useRegistryClassFallback {
            iokitRule = "(deny iokit-get-properties (iokit-registry-entry-class \"IOPlatformExpertDevice\"))"
        } else {
            iokitRule = "(deny iokit-get-properties (iokit-property \"IOPlatformSerialNumber\") (iokit-property \"IOPlatformUUID\"))"
        }
        return """
        (version 1)
        (allow default)
        (deny sysctl-read (sysctl-name "kern.hostname"))
        \(iokitRule)
        (deny file-read* (subpath "/Users/\(hostShortName)"))
        """
    }

    /// Redacts sensitive hardware/identity strings while preserving non-empty presence & prefix length.
    public static func redactSensitiveValue(_ raw: String?) -> String {
        guard let raw else { return "<nil>" }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "<empty>" }
        let prefix = String(trimmed.prefix(2))
        return "\(prefix)***(len=\(trimmed.count))"
    }
}

public struct AgentRequest: Codable, Equatable, Sendable {
    public let op: String
    public let text: String?

    public init(op: String, text: String? = nil) {
        self.op = op
        self.text = text
    }
}

public struct AgentResponse: Codable, Equatable, Sendable {
    public let ok: Bool
    public let op: String
    public let text: String?
    public let error: String?

    public init(ok: Bool, op: String, text: String? = nil, error: String? = nil) {
        self.ok = ok
        self.op = op
        self.text = text
        self.error = error
    }
}

public struct ProbeAccessItem: Codable, Equatable, Sendable {
    public let target: String
    public let accessible: Bool
    public let errorCode: String
    public let detail: String

    public init(target: String, accessible: Bool, errorCode: String, detail: String) {
        self.target = target
        self.accessible = accessible
        self.errorCode = errorCode
        self.detail = detail
    }

    enum CodingKeys: String, CodingKey {
        case target
        case accessible
        case errorCode = "error_code"
        case detail
    }
}

public struct ProbeSuiteReport: Codable, Equatable, Sendable {
    public let schema: String
    public let boxUser: String
    public let euid: UInt32
    public let egid: UInt32
    public let s2aFile: [String: JSONValue]
    public let s2bKeychain: [String: JSONValue]
    public let s2cClipboard: [String: JSONValue]
    public let s2dTcc: [String: JSONValue]
    public let s2eProcess: [String: JSONValue]
    public let s2fIdentity: [String: JSONValue]
    public let s2gNetwork: [String: JSONValue]
    public let s2hCrossBox: [String: JSONValue]

    public init(
        schema: String = BoxConstants.evidenceSchema,
        boxUser: String,
        euid: UInt32,
        egid: UInt32,
        s2aFile: [String: JSONValue],
        s2bKeychain: [String: JSONValue],
        s2cClipboard: [String: JSONValue],
        s2dTcc: [String: JSONValue],
        s2eProcess: [String: JSONValue],
        s2fIdentity: [String: JSONValue],
        s2gNetwork: [String: JSONValue],
        s2hCrossBox: [String: JSONValue]
    ) {
        self.schema = schema
        self.boxUser = boxUser
        self.euid = euid
        self.egid = egid
        self.s2aFile = s2aFile
        self.s2bKeychain = s2bKeychain
        self.s2cClipboard = s2cClipboard
        self.s2dTcc = s2dTcc
        self.s2eProcess = s2eProcess
        self.s2fIdentity = s2fIdentity
        self.s2gNetwork = s2gNetwork
        self.s2hCrossBox = s2hCrossBox
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case boxUser = "box_user"
        case euid
        case egid
        case s2aFile = "s2a_file"
        case s2bKeychain = "s2b_keychain"
        case s2cClipboard = "s2c_clipboard"
        case s2dTcc = "s2d_tcc"
        case s2eProcess = "s2e_process"
        case s2fIdentity = "s2f_identity"
        case s2gNetwork = "s2g_network"
        case s2hCrossBox = "s2h_cross_box"
    }
}
