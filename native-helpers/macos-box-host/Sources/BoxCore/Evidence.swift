import Foundation

public enum ExperimentStatus: String, Codable, Equatable, Sendable {
    case pass
    case fail
    case partial
    case blocked
    case notRun = "not_run"
}

public enum Verdict: String, Codable, Equatable, Sendable {
    case go
    case partial
    case noGo = "no-go"
}

public enum JSONValue: Codable, Equatable, Sendable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if let int = try? container.decode(Int.self) {
            self = .int(int)
        } else if let double = try? container.decode(Double.self) {
            self = .double(double)
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let array = try? container.decode([JSONValue].self) {
            self = .array(array)
        } else if let object = try? container.decode([String: JSONValue].self) {
            self = .object(object)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported JSON value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let v):
            try container.encode(v)
        case .int(let v):
            try container.encode(v)
        case .double(let v):
            try container.encode(v)
        case .bool(let v):
            try container.encode(v)
        case .array(let v):
            try container.encode(v)
        case .object(let v):
            try container.encode(v)
        case .null:
            try container.encodeNil()
        }
    }
}

public struct HostInfo: Codable, Equatable, Sendable {
    public let osVersion: String
    public let build: String
    public let arch: String
    public let modelRedacted: Bool

    public init(osVersion: String, build: String, arch: String, modelRedacted: Bool = true) {
        self.osVersion = osVersion
        self.build = build
        self.arch = arch
        self.modelRedacted = modelRedacted
    }

    enum CodingKeys: String, CodingKey {
        case osVersion = "os_version"
        case build
        case arch
        case modelRedacted = "model_redacted"
    }
}

public struct BoxEvidence: Codable, Equatable, Sendable {
    public let boxId: String
    public let uid: UInt32
    public let gid: UInt32
    public let homeMode: String
    public let groups: [String]?
    public let idOutput: String?

    public init(
        boxId: String,
        uid: UInt32,
        gid: UInt32,
        homeMode: String,
        groups: [String]? = nil,
        idOutput: String? = nil
    ) {
        self.boxId = boxId
        self.uid = uid
        self.gid = gid
        self.homeMode = homeMode
        self.groups = groups
        self.idOutput = idOutput
    }

    enum CodingKeys: String, CodingKey {
        case boxId = "box_id"
        case uid
        case gid
        case homeMode = "home_mode"
        case groups
        case idOutput = "id_output"
    }
}

public struct AppEvidence: Codable, Equatable, Sendable {
    public let appId: String
    public let version: String
    public let teamId: String

    public init(appId: String, version: String, teamId: String) {
        self.appId = appId
        self.version = version
        self.teamId = teamId
    }

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
        case version
        case teamId = "team_id"
    }
}

public struct ExperimentResult: Codable, Equatable, Sendable {
    public let experimentId: String
    public let appId: String?
    public let boxId: String?
    public let variant: String?
    public let result: ExperimentStatus
    public let measurements: [String: JSONValue]
    public let notes: String
    public let artifacts: [String]

    public init(
        experimentId: String,
        appId: String? = nil,
        boxId: String? = nil,
        variant: String? = nil,
        result: ExperimentStatus,
        measurements: [String: JSONValue] = [:],
        notes: String = "",
        artifacts: [String] = []
    ) {
        self.experimentId = experimentId
        self.appId = appId
        self.boxId = boxId
        self.variant = variant
        self.result = result
        self.measurements = measurements
        self.notes = notes
        self.artifacts = artifacts
    }

    enum CodingKeys: String, CodingKey {
        case experimentId = "experiment_id"
        case appId = "app_id"
        case boxId = "box_id"
        case variant
        case result
        case measurements
        case notes
        case artifacts
    }
}

public struct DecisionSummary: Codable, Equatable, Sendable {
    public let verdict: Verdict
    public let rationale: String

    public init(verdict: Verdict, rationale: String) {
        self.verdict = verdict
        self.rationale = rationale
    }
}

public struct EvidenceDocument: Codable, Equatable, Sendable {
    public let schema: String
    public let host: HostInfo
    public var variantSelected: String?
    public var boxes: [BoxEvidence]
    public var apps: [AppEvidence]
    public var results: [ExperimentResult]
    public var decision: DecisionSummary?

    public init(
        schema: String = BoxConstants.evidenceSchema,
        host: HostInfo,
        variantSelected: String? = nil,
        boxes: [BoxEvidence] = [],
        apps: [AppEvidence] = [],
        results: [ExperimentResult] = [],
        decision: DecisionSummary? = nil
    ) {
        self.schema = schema
        self.host = host
        self.variantSelected = variantSelected
        self.boxes = boxes
        self.apps = apps
        self.results = results
        self.decision = decision
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case host
        case variantSelected = "variant_selected"
        case boxes
        case apps
        case results
        case decision
    }
}

public enum EvidenceCodec {
    public static func encode(_ document: EvidenceDocument) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(document)
    }

    public static func decode(_ data: Data) throws -> EvidenceDocument {
        let decoder = JSONDecoder()
        return try decoder.decode(EvidenceDocument.self, from: data)
    }

    public static func renderMarkdownReport(_ document: EvidenceDocument) -> String {
        var lines: [String] = []
        lines.append("# S1 原型验证报告（原生窗口 GUI Box）")
        lines.append("")
        lines.append("- Schema: `\(document.schema)`")
        lines.append("- Host: macOS `\(document.host.osVersion)` (`\(document.host.build)`), arch `\(document.host.arch)`")
        lines.append("- Selected Launch Variant: `\(document.variantSelected ?? "none")`")
        if let decision = document.decision {
            lines.append("- Verdict: **\(decision.verdict.rawValue)**")
            lines.append("- Rationale: \(decision.rationale)")
        }
        lines.append("")
        lines.append("## Boxes")
        lines.append("")
        if document.boxes.isEmpty {
            lines.append("_None recorded._")
        } else {
            lines.append("| box_id | uid | gid | home_mode |")
            lines.append("| --- | --- | --- | --- |")
            for box in document.boxes {
                lines.append("| `\(box.boxId)` | `\(box.uid)` | `\(box.gid)` | `\(box.homeMode)` |")
            }
        }
        lines.append("")
        lines.append("## Apps")
        lines.append("")
        if document.apps.isEmpty {
            lines.append("_None recorded._")
        } else {
            lines.append("| app_id | version | team_id |")
            lines.append("| --- | --- | --- |")
            for app in document.apps {
                lines.append("| `\(app.appId)` | `\(app.version)` | `\(app.teamId)` |")
            }
        }
        lines.append("")
        lines.append("## Experiment Results")
        lines.append("")
        if document.results.isEmpty {
            lines.append("_No experiment results recorded._")
        } else {
            lines.append("| experiment_id | app_id | box_id | variant | result | notes |")
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for item in document.results {
                let app = item.appId ?? "-"
                let box = item.boxId ?? "-"
                let variant = item.variant ?? "-"
                let note = item.notes.replacingOccurrences(of: "|", with: "\\|")
                lines.append("| `\(item.experimentId)` | `\(app)` | `\(box)` | `\(variant)` | `\(item.result.rawValue)` | \(note) |")
            }
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }
}
