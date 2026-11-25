import BoxCore
import Darwin
import Foundation

struct BoxAccountRecord: Codable {
    let shortName: String
    let boxId: String?
    let uid: UInt32?
    let primaryGid: UInt32?
    let homeDirectory: String?
    let isHidden: String?
    let comment: String?
    let managed: Bool
    let validationError: String?

    enum CodingKeys: String, CodingKey {
        case shortName = "short_name"
        case boxId = "box_id"
        case uid
        case primaryGid = "primary_gid"
        case homeDirectory = "home_directory"
        case isHidden = "is_hidden"
        case comment
        case managed
        case validationError = "validation_error"
    }
}

enum BoxLifecycle {
    static func requireRoot(for action: String) throws {
        if geteuid() != 0 {
            throw BoxCLIError.requiresRoot(action)
        }
    }

    static func readAttribute(user shortName: String, key: String) -> String? {
        guard let result = try? ProcessRunner.run(DsclCommandBuilder.readUser(shortName: shortName, key: key)),
              result.succeeded else {
            return nil
        }
        return DsclParser.parseSingleAttribute(result.stdout, key: key)
    }

    static func readGroupGid(_ groupName: String) -> UInt32? {
        guard let result = try? ProcessRunner.run(DsclCommandBuilder.readGroup(groupName: groupName, key: "PrimaryGroupID")),
              result.succeeded,
              let raw = DsclParser.parseSingleAttribute(result.stdout, key: "PrimaryGroupID") else {
            return nil
        }
        return UInt32(raw)
    }

    static func userExists(_ shortName: String) -> Bool {
        guard let result = try? ProcessRunner.run(DsclCommandBuilder.readUser(shortName: shortName, key: "UniqueID")) else {
            return false
        }
        return result.succeeded
    }

    static func inspectAccount(shortName: String) -> BoxAccountRecord {
        let uid = readAttribute(user: shortName, key: "UniqueID").flatMap(UInt32.init)
        let gid = readAttribute(user: shortName, key: "PrimaryGroupID").flatMap(UInt32.init)
        let home = readAttribute(user: shortName, key: "NFSHomeDirectory")
        let hidden = readAttribute(user: shortName, key: "IsHidden")
        let comment = readAttribute(user: shortName, key: "Comment")

        do {
            let identifier = try BoxAccountGuard.validateManagedAccount(shortName: shortName, comment: comment)
            return BoxAccountRecord(
                shortName: shortName,
                boxId: identifier.boxId,
                uid: uid,
                primaryGid: gid,
                homeDirectory: home,
                isHidden: hidden,
                comment: comment,
                managed: true,
                validationError: nil
            )
        } catch {
            return BoxAccountRecord(
                shortName: shortName,
                boxId: nil,
                uid: uid,
                primaryGid: gid,
                homeDirectory: home,
                isHidden: hidden,
                comment: comment,
                managed: false,
                validationError: error.description
            )
        }
    }

    static func listPrefixedAccounts() throws -> [BoxAccountRecord] {
        let listResult = try ProcessRunner.run(DsclCommandBuilder.listUsers())
        guard listResult.succeeded else {
            throw BoxCLIError.commandFailed("dscl list /Users", listResult.stderr)
        }
        let names = listResult.stdout
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.hasPrefix(BoxConstants.userPrefix) }
            .sorted()
        return names.map(inspectAccount(shortName:))
    }

    static func generateRandomSecretHex(byteCount: Int = 32) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        guard status == errSecSuccess else {
            throw BoxCLIError.internalError("SecRandomCopyBytes failed with status \(status)")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func ensureGroupWithStatus(name: String, minGid: UInt32) throws -> (gid: UInt32, created: Bool) {
        if let existing = readGroupGid(name) {
            return (existing, false)
        }
        let groupsResult = try ProcessRunner.run(DsclCommandBuilder.listGroupIds())
        guard groupsResult.succeeded else {
            throw BoxCLIError.commandFailed("dscl list /Groups PrimaryGroupID", groupsResult.stderr)
        }
        let usedGids = Set(DsclParser.parseIdList(groupsResult.stdout).values)
        let newGid = DsclParser.nextAvailableId(existing: usedGids, startingAt: minGid)
        let createResult = try ProcessRunner.run(DsclCommandBuilder.createGroup(groupName: name, gid: newGid))
        guard createResult.succeeded else {
            throw BoxCLIError.commandFailed("dseditgroup create \(name)", createResult.stderr)
        }
        return (newGid, true)
    }

    static func ensureGroup(name: String, minGid: UInt32) throws -> UInt32 {
        try ensureGroupWithStatus(name: name, minGid: minGid).gid
    }

    static func provision(boxId rawBoxId: String) throws -> BoxEvidence {
        try requireRoot(for: "provision")
        let identifier = try BoxIdentifier(rawBoxId)

        if userExists(identifier.shortName) {
            throw BoxCLIError.alreadyExists("User \(identifier.shortName) already exists")
        }

        let primaryGroup = try ensureGroupWithStatus(name: BoxConstants.primaryGroupName, minGid: BoxConstants.minGid)
        let primaryGid = primaryGroup.gid
        var createdDirectoryRecords: [PrototypeDirectoryRecord] = []

        func appendDirectoryRecord(path: String, created: Bool) throws {
            if let record = try directoryRecordIfCreated(path: path, created: created) {
                createdDirectoryRecords.append(record)
            }
        }

        let runtimeRootCreated = try ensureDirectoryOwned(
            path: BoxConstants.sharedRuntimeRootDirectory,
            uid: 0,
            gid: 0,
            mode: 0o755
        )
        try appendDirectoryRecord(path: BoxConstants.sharedRuntimeRootDirectory, created: runtimeRootCreated)
        let runtimeBoxesCreated = try ensureDirectoryOwned(
            path: BoxConstants.runtimeDirectory,
            uid: 0,
            gid: 0,
            mode: 0o755
        )
        try appendDirectoryRecord(path: BoxConstants.runtimeDirectory, created: runtimeBoxesCreated)

        let usersResult = try ProcessRunner.run(DsclCommandBuilder.listUserUniqueIds())
        guard usersResult.succeeded else {
            throw BoxCLIError.commandFailed("dscl list /Users UniqueID", usersResult.stderr)
        }
        let usedUids = Set(DsclParser.parseIdList(usersResult.stdout).values)
        let newUid = DsclParser.nextAvailableId(existing: usedUids, startingAt: BoxConstants.minUid)

        for cmd in DsclCommandBuilder.createUserCommands(id: identifier, uid: newUid, primaryGid: primaryGid) {
            let result = try ProcessRunner.run(cmd)
            guard result.succeeded else {
                throw BoxCLIError.commandFailed(cmd.displayShellCommand, result.stderr)
            }
        }

        let password = try generateRandomSecretHex(byteCount: 32)
        let passwdCmd = DsclCommandBuilder.setPassword(id: identifier, password: password)
        let passwdResult = try ProcessRunner.run(passwdCmd)
        guard passwdResult.succeeded else {
            throw BoxCLIError.commandFailed(passwdCmd.displayShellCommand, passwdResult.stderr)
        }

        let secretDirCreated = try ensureDirectoryOwned(path: BoxConstants.secretDirectory, uid: 0, gid: 0, mode: 0o700)
        try appendDirectoryRecord(path: BoxConstants.secretDirectory, created: secretDirCreated)
        try writeSecretFile(password: password, to: identifier.secretPath)

        let fm = FileManager.default
        let managedHomePaths = [identifier.homeDirectory, identifier.applicationsDirectory, identifier.inboxDirectory]
        let preexistingHomePaths = Set(managedHomePaths.filter { fm.fileExists(atPath: $0) })

        let homeCmd = DsclCommandBuilder.createHomeDirectory(id: identifier)
        let homeResult = try ProcessRunner.run(homeCmd)
        guard homeResult.succeeded else {
            throw BoxCLIError.commandFailed(homeCmd.displayShellCommand, homeResult.stderr)
        }

        for path in managedHomePaths {
            _ = try ensureDirectoryOwned(path: path, uid: newUid, gid: primaryGid, mode: 0o700)
            try appendDirectoryRecord(path: path, created: !preexistingHomePaths.contains(path))
        }

        let idResult = try ProcessRunner.run(CommandSpec(executable: "/usr/bin/id", arguments: [identifier.shortName]))
        let idOutput = idResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)

        let groupsResult = try ProcessRunner.run(CommandSpec(executable: "/usr/bin/id", arguments: ["-Gn", identifier.shortName]))
        let groups = groupsResult.stdout
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)

        let homeMode = try octalPermissions(of: identifier.homeDirectory)

        try writePrototypeManifest(
            groupRecord: PrototypeGroupRecord(
                name: BoxConstants.primaryGroupName,
                gid: primaryGid,
                createdByTool: primaryGroup.created
            ),
            directoryRecords: createdDirectoryRecords
        )

        return BoxEvidence(
            boxId: identifier.boxId,
            uid: newUid,
            gid: primaryGid,
            homeMode: homeMode,
            groups: groups,
            idOutput: idOutput
        )
    }

    static func writeSecretFile(password: String, to path: String) throws {
        let fm = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent
        if !fm.fileExists(atPath: dir) {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }
        try setOwnerAndMode(path: dir, uid: 0, gid: 0, mode: 0o700)

        let data = Data((password + "\n").utf8)
        let url = URL(fileURLWithPath: path)
        try data.write(to: url, options: .atomic)
        try setOwnerAndMode(path: path, uid: 0, gid: 0, mode: 0o600)
    }

    static func setOwnerAndMode(path: String, uid: UInt32, gid: UInt32, mode: mode_t) throws {
        if chown(path, uid, gid) != 0 {
            throw BoxCLIError.internalError("chown(\(path), \(uid), \(gid)) failed: errno=\(errno)")
        }
        if chmod(path, mode) != 0 {
            throw BoxCLIError.internalError("chmod(\(path), \(String(mode, radix: 8))) failed: errno=\(errno)")
        }
    }

    static func ensureDirectoryOwned(path: String, uid: UInt32, gid: UInt32, mode: mode_t) throws -> Bool {
        let fm = FileManager.default
        let existed = fm.fileExists(atPath: path)
        if existed {
            guard let observation = observeDirectory(path: path), observation.isDirectory else {
                throw BoxCLIError.guardrailRejected("Refusing non-directory or symlink at required directory path: \(path)")
            }
        } else {
            try fm.createDirectory(atPath: path, withIntermediateDirectories: true)
        }
        try setOwnerAndMode(path: path, uid: uid, gid: gid, mode: mode)
        return !existed
    }

    static func observeDirectory(path: String) -> PrototypeDirectoryObservation? {
        var st = stat()
        guard lstat(path, &st) == 0 else {
            return nil
        }
        return PrototypeDirectoryObservation(
            inode: UInt64(st.st_ino),
            ownerUid: UInt32(st.st_uid),
            isDirectory: (st.st_mode & S_IFMT) == S_IFDIR
        )
    }

    static func directoryRecordIfCreated(path: String, created: Bool) throws -> PrototypeDirectoryRecord? {
        guard created, let observation = observeDirectory(path: path), observation.isDirectory else {
            return nil
        }
        return PrototypeDirectoryRecord(path: path, inode: observation.inode, ownerUid: observation.ownerUid)
    }

    static func loadPrototypeManifest() -> PrototypeManifest? {
        guard let data = FileManager.default.contents(atPath: BoxConstants.prototypeManifestPath) else {
            return nil
        }
        return try? PrototypeManifestCodec.decode(data)
    }

    static func writePrototypeManifest(
        groupRecord: PrototypeGroupRecord,
        directoryRecords: [PrototypeDirectoryRecord]
    ) throws {
        _ = try ensureDirectoryOwned(path: BoxConstants.prototypeStateDirectory, uid: 0, gid: 0, mode: 0o700)
        var manifest = loadPrototypeManifest() ?? PrototypeManifest()
        manifest = manifest.addingGroup(groupRecord)
        for record in directoryRecords {
            manifest = manifest.addingCreatedDirectory(record)
        }
        let data = try PrototypeManifestCodec.encode(manifest)
        try data.write(to: URL(fileURLWithPath: BoxConstants.prototypeManifestPath))
        try setOwnerAndMode(path: BoxConstants.prototypeManifestPath, uid: 0, gid: 0, mode: 0o600)
    }

    static func octalPermissions(of path: String) throws -> String {
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        guard let number = attrs[.posixPermissions] as? NSNumber else {
            return "unknown"
        }
        return String(format: "%04o", number.intValue & 0o7777)
    }

    static func destroy(
        boxId: String?,
        rawTargetUser: String?,
        allPrototype: Bool,
        apply: Bool
    ) throws {
        let candidates: [BoxAccountRecord]
        let expectedConfirmation: String

        if allPrototype {
            candidates = try listPrefixedAccounts()
            expectedConfirmation = "all-prototype"
        } else if let rawTargetUser {
            guard userExists(rawTargetUser) else {
                throw BoxCLIError.notFound("Account '\(rawTargetUser)' does not exist")
            }
            candidates = [inspectAccount(shortName: rawTargetUser)]
            expectedConfirmation = rawTargetUser
        } else if let boxId {
            let identifier = try BoxIdentifier(boxId)
            guard userExists(identifier.shortName) else {
                throw BoxCLIError.notFound("Box user '\(identifier.shortName)' does not exist")
            }
            candidates = [inspectAccount(shortName: identifier.shortName)]
            expectedConfirmation = identifier.boxId
        } else {
            throw BoxCLIError.invalidArguments("destroy requires <box_id>, --target-user <short_name>, or --all-prototype")
        }

        var approved: [(BoxIdentifier, BoxAccountRecord)] = []
        var rejected: [BoxAccountRecord] = []

        for record in candidates {
            do {
                let id = try BoxAccountGuard.validateManagedAccount(
                    shortName: record.shortName,
                    comment: record.comment
                )
                approved.append((id, record))
            } catch {
                rejected.append(record)
            }
        }

        if !rejected.isEmpty {
            fputs("GUARDRAIL REJECTED the following account(s) (must have 'atombox_' prefix AND Comment='atomium-box:<box_id>'):\n", stderr)
            for r in rejected {
                fputs("  - \(r.shortName): \(r.validationError ?? "failed guardrail")\n", stderr)
            }
            if !allPrototype {
                throw BoxCLIError.guardrailRejected(rejected[0].validationError ?? "Account failed safety guardrail")
            }
        }

        if approved.isEmpty {
            print("No managed Atomium prototype Box accounts found to destroy.")
        }

        print(apply ? "=== DESTROY PLAN (APPLY MODE) ===" : "=== DESTROY PLAN (DRY-RUN) ===")
        for (id, record) in approved {
            print("  Account : \(id.shortName) (uid=\(record.uid.map(String.init) ?? "?"), Comment=\(record.comment ?? "<none>"))")
            print("  Home    : \(record.homeDirectory ?? id.homeDirectory)")
            print("  Secret  : \(id.secretPath)")
            print("  Socket  : \(id.socketDirectory)")
        }
        if allPrototype {
            printCleanupRemainderPreview(apply: apply)
        }

        guard apply else {
            print("Dry-run only. No accounts or files were modified. Re-run with --apply (and sudo) to execute.")
            return
        }

        try requireRoot(for: "destroy --apply")
        fputs("Type '\(expectedConfirmation)' to confirm permanent deletion: ", stdout)
        fflush(stdout)
        guard let input = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines),
              input == expectedConfirmation else {
            throw BoxCLIError.aborted("Confirmation mismatch; aborting destroy without making changes.")
        }

        let fm = FileManager.default
        for (id, record) in approved {
            if let uid = record.uid {
                _ = try? ProcessRunner.run(CommandSpec(executable: "/bin/launchctl", arguments: ["bootout", "user/\(uid)"]))
                _ = try? ProcessRunner.run(CommandSpec(executable: "/usr/bin/pkill", arguments: ["-KILL", "-u", String(uid)]))
            }

            let delCmd = DsclCommandBuilder.deleteUser(id: id)
            let delResult = try ProcessRunner.run(delCmd)
            guard delResult.succeeded else {
                throw BoxCLIError.commandFailed(delCmd.displayShellCommand, delResult.stderr)
            }

            let homePath = record.homeDirectory ?? id.homeDirectory
            if homePath.hasPrefix("/Users/\(BoxConstants.userPrefix)") && fm.fileExists(atPath: homePath) {
                try fm.removeItem(atPath: homePath)
            }
            if fm.fileExists(atPath: id.secretPath) {
                try fm.removeItem(atPath: id.secretPath)
            }
            if fm.fileExists(atPath: id.socketDirectory) {
                try fm.removeItem(atPath: id.socketDirectory)
            }
            print("Destroyed \(id.shortName).")
        }

        if allPrototype {
            let remaining = try listPrefixedAccounts()
            if remaining.isEmpty {
                try cleanupSharedPrototypeArtifacts()
            } else {
                fputs("Note: \(remaining.count) unmanaged atombox_* account(s) still exist; skipping group removal.\n", stderr)
            }
        }
    }

    static func printCleanupRemainderPreview(apply: Bool) {
        print("  Groups  : \(BoxConstants.primaryGroupName), \(BoxConstants.controlGroupName) (if present and no managed accounts remain)")
        print("  Dirs    : \(BoxConstants.secretDirectory), \(BoxConstants.sharedRuntimeRootDirectory) (only when owned according to \(BoxConstants.prototypeManifestPath))")
        if !apply {
            print("  (Only removed when --all-prototype --apply is confirmed)")
        }
    }

    static func cleanupSharedPrototypeArtifacts() throws {
        let manifest = loadPrototypeManifest()
        if manifest == nil {
            fputs("Warning: prototype manifest missing or unreadable at \(BoxConstants.prototypeManifestPath); no shared groups or directories will be removed.\n", stderr)
            return
        }

        for group in [BoxConstants.primaryGroupName, BoxConstants.controlGroupName] {
            let decision = PrototypeCleanupEvaluator.groupDecision(
                manifest: manifest,
                groupName: group,
                currentGid: readGroupGid(group)
            )
            guard decision.shouldDelete else {
                print("Skipping group '\(group)': \(decision.skipReason).")
                continue
            }
            let res = try ProcessRunner.run(DsclCommandBuilder.deleteGroup(groupName: group))
            if res.succeeded {
                print("Deleted group '\(group)'.")
            } else {
                fputs("Warning: failed to delete group '\(group)': \(res.stderr)\n", stderr)
            }
        }

        let fm = FileManager.default
        for dir in [BoxConstants.secretDirectory, BoxConstants.sharedRuntimeRootDirectory] {
            let decision = PrototypeCleanupEvaluator.directoryDecision(
                manifest: manifest,
                path: dir,
                current: observeDirectory(path: dir)
            )
            guard decision.shouldDelete else {
                print("Skipping directory '\(dir)': \(decision.skipReason).")
                continue
            }
            do {
                try fm.removeItem(atPath: dir)
                print("Removed directory '\(dir)'.")
            } catch {
                fputs("Warning: failed to remove directory '\(dir)': \(error.localizedDescription)\n", stderr)
            }
        }
    }
}

enum BoxCLIError: Error, CustomStringConvertible {
    case invalidArguments(String)
    case requiresRoot(String)
    case alreadyExists(String)
    case notFound(String)
    case guardrailRejected(String)
    case aborted(String)
    case commandFailed(String, String)
    case internalError(String)

    var description: String {
        switch self {
        case .invalidArguments(let msg): return "Invalid arguments: \(msg)"
        case .requiresRoot(let action): return "Subcommand '\(action)' requires root (run via sudo in Terminal)."
        case .alreadyExists(let msg): return msg
        case .notFound(let msg): return msg
        case .guardrailRejected(let msg): return "Guardrail rejected: \(msg)"
        case .aborted(let msg): return msg
        case .commandFailed(let cmd, let err): return "Command failed (\(cmd)): \(err.trimmingCharacters(in: .whitespacesAndNewlines))"
        case .internalError(let msg): return "Internal error: \(msg)"
        }
    }
}
