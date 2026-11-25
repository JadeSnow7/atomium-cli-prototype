import Foundation

public struct PrototypeGroupRecord: Codable, Equatable, Sendable {
    public let name: String
    public let gid: UInt32
    public let createdByTool: Bool

    public init(name: String, gid: UInt32, createdByTool: Bool) {
        self.name = name
        self.gid = gid
        self.createdByTool = createdByTool
    }

    enum CodingKeys: String, CodingKey {
        case name
        case gid
        case createdByTool = "created_by_tool"
    }
}

public struct PrototypeDirectoryRecord: Codable, Equatable, Sendable {
    public let path: String
    public let inode: UInt64
    public let ownerUid: UInt32
    public let createdByTool: Bool

    public init(path: String, inode: UInt64, ownerUid: UInt32, createdByTool: Bool = true) {
        self.path = path
        self.inode = inode
        self.ownerUid = ownerUid
        self.createdByTool = createdByTool
    }

    enum CodingKeys: String, CodingKey {
        case path
        case inode
        case ownerUid = "owner_uid"
        case createdByTool = "created_by_tool"
    }
}

public struct PrototypeManifest: Codable, Equatable, Sendable {
    public static let currentSchema = "atomium-s1-prototype-manifest-v1"

    public let schema: String
    public let groups: [PrototypeGroupRecord]
    public let directories: [PrototypeDirectoryRecord]

    public init(
        schema: String = PrototypeManifest.currentSchema,
        groups: [PrototypeGroupRecord] = [],
        directories: [PrototypeDirectoryRecord] = []
    ) {
        self.schema = schema
        self.groups = groups
        self.directories = directories
    }

    public func addingGroup(_ record: PrototypeGroupRecord) -> PrototypeManifest {
        guard let index = groups.firstIndex(where: { $0.name == record.name }) else {
            return PrototypeManifest(schema: schema, groups: groups + [record], directories: directories)
        }
        var merged = groups
        let existing = merged[index]
        merged[index] = PrototypeGroupRecord(
            name: existing.name,
            gid: existing.gid,
            createdByTool: existing.createdByTool || record.createdByTool
        )
        return PrototypeManifest(schema: schema, groups: merged, directories: directories)
    }

    public func addingCreatedDirectory(_ record: PrototypeDirectoryRecord) -> PrototypeManifest {
        guard !directories.contains(where: { $0.path == record.path }) else {
            return self
        }
        return PrototypeManifest(schema: schema, groups: groups, directories: directories + [record])
    }
}

public enum PrototypeManifestError: Error, Equatable, CustomStringConvertible, Sendable {
    case unsupportedSchema(String)

    public var description: String {
        switch self {
        case .unsupportedSchema(let schema):
            return "Unsupported prototype manifest schema '\(schema)'"
        }
    }
}

public enum PrototypeManifestCodec {
    public static func encode(_ manifest: PrototypeManifest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(manifest)
    }

    public static func decode(_ data: Data) throws -> PrototypeManifest {
        let manifest = try JSONDecoder().decode(PrototypeManifest.self, from: data)
        guard manifest.schema == PrototypeManifest.currentSchema else {
            throw PrototypeManifestError.unsupportedSchema(manifest.schema)
        }
        return manifest
    }
}

public struct PrototypeDirectoryObservation: Equatable, Sendable {
    public let inode: UInt64
    public let ownerUid: UInt32
    public let isDirectory: Bool

    public init(inode: UInt64, ownerUid: UInt32, isDirectory: Bool) {
        self.inode = inode
        self.ownerUid = ownerUid
        self.isDirectory = isDirectory
    }
}

public enum PrototypeCleanupDecision: Equatable, Sendable {
    case delete
    case alreadyAbsent
    case missingManifest
    case missingRecord
    case notCreatedByTool
    case gidMismatch(expected: UInt32, actual: UInt32)
    case inodeMismatch(expected: UInt64, actual: UInt64)
    case ownerMismatch(expected: UInt32, actual: UInt32)
    case notDirectory

    public var shouldDelete: Bool {
        self == .delete
    }

    public var skipReason: String {
        switch self {
        case .delete:
            return "eligible"
        case .alreadyAbsent:
            return "already absent"
        case .missingManifest:
            return "manifest missing or unreadable"
        case .missingRecord:
            return "no manifest record"
        case .notCreatedByTool:
            return "resource was reused or not created by this tool"
        case .gidMismatch(let expected, let actual):
            return "gid mismatch (manifest=\(expected), current=\(actual))"
        case .inodeMismatch(let expected, let actual):
            return "inode mismatch (manifest=\(expected), current=\(actual))"
        case .ownerMismatch(let expected, let actual):
            return "owner uid mismatch (manifest=\(expected), current=\(actual))"
        case .notDirectory:
            return "current path is not a directory"
        }
    }
}

public enum PrototypeCleanupEvaluator {
    public static func groupDecision(
        manifest: PrototypeManifest?,
        groupName: String,
        currentGid: UInt32?
    ) -> PrototypeCleanupDecision {
        guard let manifest else {
            return .missingManifest
        }
        guard let record = manifest.groups.first(where: { $0.name == groupName }) else {
            return .missingRecord
        }
        guard record.createdByTool else {
            return .notCreatedByTool
        }
        guard let currentGid else {
            return .alreadyAbsent
        }
        guard currentGid == record.gid else {
            return .gidMismatch(expected: record.gid, actual: currentGid)
        }
        return .delete
    }

    public static func directoryDecision(
        manifest: PrototypeManifest?,
        path: String,
        current: PrototypeDirectoryObservation?
    ) -> PrototypeCleanupDecision {
        guard let manifest else {
            return .missingManifest
        }
        guard let record = manifest.directories.first(where: { $0.path == path }) else {
            return .missingRecord
        }
        guard record.createdByTool else {
            return .notCreatedByTool
        }
        guard let current else {
            return .alreadyAbsent
        }
        guard current.isDirectory else {
            return .notDirectory
        }
        guard current.inode == record.inode else {
            return .inodeMismatch(expected: record.inode, actual: current.inode)
        }
        guard current.ownerUid == record.ownerUid else {
            return .ownerMismatch(expected: record.ownerUid, actual: current.ownerUid)
        }
        return .delete
    }
}
