import Foundation

public enum DsclParser {
    /// Parses `dscl . -list /Users UniqueID` or `dscl . -list /Groups PrimaryGroupID`
    /// into a dictionary mapping name -> numeric ID.
    public static func parseIdList(_ output: String) -> [String: UInt32] {
        var result: [String: UInt32] = [:]
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let parts = rawLine.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 2, let id = UInt32(parts.last!) else {
                continue
            }
            let name = String(parts[0])
            result[name] = id
        }
        return result
    }

    /// Finds the smallest unused ID >= `startingAt`.
    public static func nextAvailableId(existing: Set<UInt32>, startingAt: UInt32) -> UInt32 {
        var candidate = startingAt
        while existing.contains(candidate) {
            candidate += 1
        }
        return candidate
    }

    /// Parses a single-key `dscl . -read /Users/<name> <Key>` output.
    /// Handles `Key: value`, `dsAttrTypeNative:Key: value`, and multi-line `Key:\n value` formats.
    public static func parseSingleAttribute(_ output: String, key: String) -> String? {
        let lines = output.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).map(String.init)
        let prefixes = [
            "\(key):",
            "dsAttrTypeNative:\(key):",
            "dsAttrTypeStandard:\(key):",
        ]
        for (index, line) in lines.enumerated() {
            if let matchedPrefix = prefixes.first(where: { line.hasPrefix($0) }) {
                let remainder = line.dropFirst(matchedPrefix.count).trimmingCharacters(in: .whitespaces)
                if !remainder.isEmpty {
                    return remainder
                }
                if index + 1 < lines.count {
                    let next = lines[index + 1].trimmingCharacters(in: .whitespaces)
                    if !next.isEmpty {
                        return next
                    }
                }
                return ""
            }
        }
        return nil
    }
}
