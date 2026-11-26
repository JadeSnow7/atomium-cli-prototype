import Darwin
import Foundation
import XCTest
@testable import BoxCore

final class BoxCoreTests: XCTestCase {
    func testValidBoxIdentifier() throws {
        let id = try BoxIdentifier("s1a")
        XCTAssertEqual(id.boxId, "s1a")
        XCTAssertEqual(id.shortName, "atombox_s1a")
        XCTAssertEqual(id.commentMarker, "atomium-box:s1a")
        XCTAssertEqual(id.realName, "Atomium Box s1a")
        XCTAssertEqual(id.homeDirectory, "/Users/atombox_s1a")
        XCTAssertEqual(id.tmpDirectory, "/Users/atombox_s1a/.tmp")
        XCTAssertEqual(id.secretPath, "/var/db/atomium-proto/s1a.secret")
        XCTAssertEqual(id.socketPath, "/private/var/atomium-proto/boxes/s1a/agent.sock")

        let boundaryMin = try BoxIdentifier("ab")
        XCTAssertEqual(boundaryMin.shortName, "atombox_ab")

        let boundaryMax = try BoxIdentifier("a1b2c3d4e5f6g7h8")
        XCTAssertEqual(boundaryMax.shortName, "atombox_a1b2c3d4e5f6g7h8")
    }

    func testInvalidBoxIdentifiers() {
        let invalidCases = [
            "",
            "a",
            "a1b2c3d4e5f6g7h89",
            "S1A",
            "s1_a",
            "s1-a",
            "../root",
            "s1 a",
        ]
        for raw in invalidCases {
            XCTAssertThrowsError(try BoxIdentifier(raw)) { error in
                XCTAssertEqual(error as? BoxValidationError, .invalidBoxId(raw))
            }
        }
    }

    func testManagedAccountGuardrails() throws {
        let valid = try BoxAccountGuard.validateManagedAccount(
            shortName: "atombox_s1a",
            comment: "atomium-box:s1a"
        )
        XCTAssertEqual(valid.boxId, "s1a")

        let validWithNewline = try BoxAccountGuard.validateManagedAccount(
            shortName: "atombox_s1b",
            comment: "atomium-box:s1b\n"
        )
        XCTAssertEqual(validWithNewline.boxId, "s1b")

        XCTAssertThrowsError(
            try BoxAccountGuard.validateManagedAccount(
                shortName: "huaodong",
                comment: "atomium-box:huaodong"
            )
        ) { error in
            XCTAssertEqual(error as? BoxValidationError, .invalidShortNamePrefix("huaodong"))
        }

        XCTAssertThrowsError(
            try BoxAccountGuard.validateManagedAccount(
                shortName: "atombox_s1a",
                comment: nil
            )
        ) { error in
            XCTAssertEqual(error as? BoxValidationError, .missingCommentMarker(shortName: "atombox_s1a"))
        }

        XCTAssertThrowsError(
            try BoxAccountGuard.validateManagedAccount(
                shortName: "atombox_s1a",
                comment: "atomium-box:s1b"
            )
        ) { error in
            XCTAssertEqual(
                error as? BoxValidationError,
                .invalidCommentMarker(
                    shortName: "atombox_s1a",
                    expected: "atomium-box:s1a",
                    actual: "atomium-box:s1b"
                )
            )
        }

        XCTAssertThrowsError(
            try BoxAccountGuard.validateManagedAccount(
                shortName: "atombox_s1a",
                comment: ""
            )
        ) { error in
            XCTAssertEqual(
                error as? BoxValidationError,
                .invalidCommentMarker(
                    shortName: "atombox_s1a",
                    expected: "atomium-box:s1a",
                    actual: ""
                )
            )
        }
    }

    func testEmailRedaction() {
        XCTAssertEqual(BoxAccountGuard.redactEmail("alice@example.com"), "al***")
        XCTAssertEqual(BoxAccountGuard.redactEmail("a@example.com"), "a***")
        XCTAssertEqual(BoxAccountGuard.redactEmail(""), "***")
    }

    func testEvidenceJsonRoundTrip() throws {
        let doc = EvidenceDocument(
            host: HostInfo(osVersion: "26.6.2", build: "25G83", arch: "arm64", modelRedacted: true),
            variantSelected: "V2",
            boxes: [
                BoxEvidence(boxId: "s1a", uid: 701, gid: 700, homeMode: "0700")
            ],
            apps: [
                AppEvidence(appId: "claude-desktop", version: "1.2.3", teamId: "TEAM123456")
            ],
            results: [
                ExperimentResult(
                    experimentId: "S1c",
                    appId: "claude-desktop",
                    boxId: "s1a",
                    variant: "V2",
                    result: .pass,
                    measurements: [
                        "relaunch_logged_in": .bool(true),
                        "startup_ms": .int(1420),
                    ],
                    notes: "Keychain unlocked cleanly",
                    artifacts: ["screens/S1c-claude.png"]
                ),
                ExperimentResult(
                    experimentId: "S1g",
                    result: .notRun,
                    notes: "Single monitor setup"
                ),
            ],
            decision: DecisionSummary(verdict: .go, rationale: "All required gates passed")
        )

        let data = try EvidenceCodec.encode(doc)
        let jsonString = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(jsonString.contains("\"schema\" : \"atomium-s1-evidence-v1\""))
        XCTAssertTrue(jsonString.contains("\"os_version\" : \"26.6.2\""))
        XCTAssertTrue(jsonString.contains("\"model_redacted\" : true"))
        XCTAssertTrue(jsonString.contains("\"variant_selected\" : \"V2\""))
        XCTAssertTrue(jsonString.contains("\"experiment_id\" : \"S1c\""))
        XCTAssertTrue(jsonString.contains("\"result\" : \"not_run\""))
        XCTAssertTrue(jsonString.contains("\"verdict\" : \"go\""))

        let decoded = try EvidenceCodec.decode(data)
        XCTAssertEqual(decoded, doc)

        let markdown = EvidenceCodec.renderMarkdownReport(doc)
        XCTAssertTrue(markdown.contains("atomium-s1-evidence-v1"))
        XCTAssertTrue(markdown.contains("**go**"))
        XCTAssertTrue(markdown.contains("`S1c`"))
    }

    func testDsclCommandAssembly() throws {
        let id = try BoxIdentifier("s1a")
        let createGroup = DsclCommandBuilder.createGroup(groupName: BoxConstants.primaryGroupName, gid: 700)
        XCTAssertEqual(createGroup.shellCommand, "/usr/sbin/dseditgroup -o create -i 700 atombox")

        let createCommands = DsclCommandBuilder.createUserCommands(id: id, uid: 701, primaryGid: 700)
        XCTAssertEqual(createCommands.count, 8)
        XCTAssertEqual(createCommands[0].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a")
        XCTAssertEqual(createCommands[1].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a UniqueID 701")
        XCTAssertEqual(createCommands[2].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a PrimaryGroupID 700")
        XCTAssertEqual(createCommands[3].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a UserShell /usr/bin/false")
        XCTAssertEqual(createCommands[4].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a NFSHomeDirectory /Users/atombox_s1a")
        XCTAssertEqual(createCommands[5].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a RealName 'Atomium Box s1a'")
        XCTAssertEqual(createCommands[6].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a IsHidden 1")
        XCTAssertEqual(createCommands[7].shellCommand, "/usr/bin/dscl . -create /Users/atombox_s1a Comment atomium-box:s1a")

        let secret = "super-secret-value"
        let passwd = try DsclCommandBuilder.setPassword(id: id, password: secret)
        XCTAssertEqual(passwd.argv, ["/usr/bin/dscl", "."])
        XCTAssertFalse(passwd.arguments.contains(where: { $0.contains(secret) }))
        let passwdStdin = passwd.stdinData.map { String(decoding: $0, as: UTF8.self) } ?? ""
        XCTAssertTrue(passwdStdin.contains("-passwd /Users/atombox_s1a "))
        XCTAssertTrue(passwdStdin.contains(secret))
        XCTAssertFalse(passwd.displayShellCommand.contains(secret))

        let homedir = DsclCommandBuilder.createHomeDirectory(id: id)
        XCTAssertEqual(homedir.shellCommand, "/usr/sbin/createhomedir -c -u atombox_s1a")

        let deleteUser = DsclCommandBuilder.deleteUser(id: id)
        XCTAssertEqual(deleteUser.shellCommand, "/usr/bin/dscl . -delete /Users/atombox_s1a")
    }

    func testLaunchctlCommandAssembly() throws {
        let id = try BoxIdentifier("s1a")
        let appPath = "/Users/atombox_s1a/Applications/TextEdit.app"
        let exePath = "/Users/atombox_s1a/Applications/TextEdit.app/Contents/MacOS/TextEdit"
        let envPrefix = "/usr/bin/env HOME=/Users/atombox_s1a TMPDIR=/Users/atombox_s1a/.tmp USER=atombox_s1a LOGNAME=atombox_s1a"

        let v1 = try LaunchctlCommandBuilder.buildLaunchCommand(
            variant: .v1,
            id: id,
            uid: 701,
            appPath: appPath,
            executablePath: exePath
        )
        XCTAssertEqual(v1.shellCommand, "/usr/bin/sudo -u atombox_s1a -H \(envPrefix) \(exePath)")

        let v2 = try LaunchctlCommandBuilder.buildLaunchCommand(
            variant: .v2,
            id: id,
            uid: 701,
            appPath: appPath,
            executablePath: exePath
        )
        XCTAssertEqual(v2.shellCommand, "/usr/bin/sudo /bin/launchctl asuser 701 /usr/bin/sudo -u atombox_s1a -H \(envPrefix) \(exePath)")

        let v3 = try LaunchctlCommandBuilder.buildLaunchCommand(
            variant: .v3,
            id: id,
            uid: 701,
            appPath: appPath,
            executablePath: exePath,
            stdoutPath: "/Users/atombox_s1a/.tmp/out.log",
            stderrPath: "/Users/atombox_s1a/.tmp/err.log",
            arguments: ["--flag"]
        )
        XCTAssertEqual(
            v3.shellCommand,
            "/usr/bin/sudo /bin/launchctl asuser 701 /usr/bin/sudo -u atombox_s1a -H \(envPrefix) /usr/bin/open -n --env HOME=/Users/atombox_s1a --env TMPDIR=/Users/atombox_s1a/.tmp --stdout /Users/atombox_s1a/.tmp/out.log --stderr /Users/atombox_s1a/.tmp/err.log -a \(appPath) --args --flag"
        )

        let v4 = try LaunchctlCommandBuilder.buildLaunchCommand(
            variant: .v4,
            id: id,
            uid: 701,
            appPath: appPath,
            executablePath: exePath,
            loginwindowPid: 142
        )
        XCTAssertEqual(v4.shellCommand, "/usr/bin/sudo /bin/launchctl bsexec 142 /usr/bin/sudo -u atombox_s1a -H \(envPrefix) \(exePath)")

        XCTAssertThrowsError(
            try LaunchctlCommandBuilder.buildLaunchCommand(
                variant: .v4,
                id: id,
                uid: 701,
                appPath: appPath,
                executablePath: exePath,
                loginwindowPid: nil
            )
        ) { error in
            XCTAssertEqual(error as? BoxValidationError, .missingLoginwindowPid)
        }

        XCTAssertEqual(LaunchctlCommandBuilder.printUserDomain(uid: 701).shellCommand, "/bin/launchctl print user/701")
    }

    func testDsclParserAndIdAllocation() {
        let sample = """
        _www            70
        nobody          -2
        huaodong        501
        atombox_s1a     701
        atombox_s1b     702
        """
        let parsed = DsclParser.parseIdList(sample)
        XCTAssertEqual(parsed["_www"], 70)
        XCTAssertEqual(parsed["huaodong"], 501)
        XCTAssertEqual(parsed["atombox_s1a"], 701)
        XCTAssertNil(parsed["nobody"])

        let nextUid = DsclParser.nextAvailableId(existing: Set(parsed.values), startingAt: 701)
        XCTAssertEqual(nextUid, 703)

        let nextGid = DsclParser.nextAvailableId(existing: [700, 701], startingAt: 700)
        XCTAssertEqual(nextGid, 702)

        XCTAssertEqual(
            DsclParser.parseSingleAttribute("Comment: atomium-box:s1a\n", key: "Comment"),
            "atomium-box:s1a"
        )
        XCTAssertEqual(
            DsclParser.parseSingleAttribute("Comment:\n atomium-box:s1b\n", key: "Comment"),
            "atomium-box:s1b"
        )
        XCTAssertEqual(
            DsclParser.parseSingleAttribute("dsAttrTypeNative:IsHidden: 1\n", key: "IsHidden"),
            "1"
        )
        XCTAssertNil(DsclParser.parseSingleAttribute("UniqueID: 701\n", key: "Comment"))
    }

    func testSbplBuilderAndAgentCodec() throws {
        let primary = try SbplBuilder.identityPatchProfile(hostShortName: "huaodong")
        XCTAssertTrue(primary.contains("(allow default)"))
        XCTAssertTrue(primary.contains("(deny sysctl-read (sysctl-name \"kern.hostname\"))"))
        XCTAssertTrue(primary.contains("(deny iokit-get-properties (iokit-property \"IOPlatformSerialNumber\") (iokit-property \"IOPlatformUUID\"))"))
        XCTAssertTrue(primary.contains("(deny file-read* (subpath \"/Users/huaodong\"))"))

        let fallback = try SbplBuilder.identityPatchProfile(hostShortName: "huaodong", useRegistryClassFallback: true)
        XCTAssertTrue(fallback.contains("iokit-registry-entry-class \"IOPlatformExpertDevice\""))

        XCTAssertThrowsError(try SbplBuilder.identityPatchProfile(hostShortName: "bad/user"))
        XCTAssertThrowsError(try SbplBuilder.identityPatchProfile(hostShortName: ""))

        XCTAssertEqual(SbplBuilder.redactSensitiveValue("C02XYZ123456"), "C0***(len=12)")
        XCTAssertEqual(SbplBuilder.redactSensitiveValue(nil), "<nil>")

        let req = AgentRequest(op: "clip.set", text: "hello")
        let encodedReq = try JSONEncoder().encode(req)
        XCTAssertEqual(try JSONDecoder().decode(AgentRequest.self, from: encodedReq), req)

        let resp = AgentResponse(ok: true, op: "health", text: "uid=701")
        let encodedResp = try JSONEncoder().encode(resp)
        XCTAssertEqual(try JSONDecoder().decode(AgentResponse.self, from: encodedResp), resp)
    }

    func testSecurityCommandsKeepSecretsOutOfArgv() throws {
        let secret = "keychain-test-secret"
        let path = "/tmp/example.keychain-db"

        let create = try SecurityCommandBuilder.createKeychain(keychainPath: path, password: secret, expectedDirectory: "/tmp")
        XCTAssertEqual(create.arguments, ["-i"])
        XCTAssertFalse(create.arguments.contains(where: { $0.contains(secret) }))
        let createStdin = create.stdinData.map { String(decoding: $0, as: UTF8.self) } ?? ""
        XCTAssertTrue(createStdin.hasPrefix("create-keychain -p "))
        XCTAssertTrue(createStdin.contains(secret))
        XCTAssertFalse(create.displayShellCommand.contains(secret))

        let unlock = try SecurityCommandBuilder.unlockKeychain(keychainPath: path, password: secret, expectedDirectory: "/tmp")
        XCTAssertEqual(unlock.arguments, ["-i"])
        XCTAssertFalse(unlock.arguments.contains(where: { $0.contains(secret) }))
        let unlockStdin = unlock.stdinData.map { String(decoding: $0, as: UTF8.self) } ?? ""
        XCTAssertTrue(unlockStdin.contains(secret))
        XCTAssertFalse(unlock.displayShellCommand.contains(secret))
    }

    func testProcessRunnerWritesAndClosesStdin() throws {
        let payload = "stdin-payload-without-trailing-newline"
        let result = try ProcessRunner.run(
            CommandSpec(
                executable: "/bin/cat",
                arguments: [],
                stdinData: Data(payload.utf8)
            )
        )
        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.stdout, payload)
    }

    func testPrototypeManifestCodecAndCleanupDecisions() throws {
        XCTAssertEqual(
            PrototypeCleanupEvaluator.groupDecision(manifest: nil, groupName: "atombox", currentGid: 700),
            .missingManifest
        )

        let reusedGroup = PrototypeGroupRecord(name: "atombox", gid: 700, createdByTool: false)
        let reusedManifest = PrototypeManifest(groups: [reusedGroup], directories: [])
        XCTAssertEqual(
            PrototypeCleanupEvaluator.groupDecision(manifest: reusedManifest, groupName: "atombox", currentGid: 700),
            .notCreatedByTool
        )

        let directory = PrototypeDirectoryRecord(path: "/private/var/atomium-proto", inode: 12345, ownerUid: 0)
        let ownedGroup = PrototypeGroupRecord(name: "atombox", gid: 700, createdByTool: true)
        let manifest = PrototypeManifest(groups: [ownedGroup], directories: [directory])

        let encoded = try PrototypeManifestCodec.encode(manifest)
        let json = String(decoding: encoded, as: UTF8.self)
        XCTAssertTrue(json.contains("\"created_by_tool\""))
        XCTAssertTrue(json.contains("\"owner_uid\""))
        XCTAssertEqual(try PrototypeManifestCodec.decode(encoded), manifest)

        XCTAssertEqual(
            PrototypeCleanupEvaluator.directoryDecision(
                manifest: manifest,
                path: directory.path,
                current: PrototypeDirectoryObservation(inode: 999, ownerUid: 0, isDirectory: true)
            ),
            .inodeMismatch(expected: 12345, actual: 999)
        )
        XCTAssertEqual(
            PrototypeCleanupEvaluator.directoryDecision(
                manifest: manifest,
                path: directory.path,
                current: PrototypeDirectoryObservation(inode: 12345, ownerUid: 0, isDirectory: true)
            ),
            .delete
        )
        XCTAssertEqual(
            PrototypeCleanupEvaluator.groupDecision(manifest: manifest, groupName: "atombox", currentGid: 700),
            .delete
        )
    }
    func testReviewDsclMarkersOverrideZeroExitStatus() {
        XCTAssertFalse(DsclParser.commandSucceeded(ProcessResult(exitCode: 0, stdout: "DS Error: -14090", stderr: "")))
        XCTAssertFalse(DsclParser.commandSucceeded(ProcessResult(exitCode: 0, stdout: "", stderr: "eDSAuthFailed")))
        XCTAssertTrue(DsclParser.commandSucceeded(ProcessResult(exitCode: 0, stdout: "normal output", stderr: "")))
    }

    func testReviewManifestReplacesStaleIdentity() {
        let old = PrototypeManifest(groups: [PrototypeGroupRecord(name: "test", gid: 700, createdByTool: true)],
            directories: [PrototypeDirectoryRecord(path: "/tmp/test", inode: 1, ownerUid: 0)])
        let updated = old.addingGroup(PrototypeGroupRecord(name: "test", gid: 701, createdByTool: false))
            .addingCreatedDirectory(PrototypeDirectoryRecord(path: "/tmp/test", inode: 2, ownerUid: 0))
        XCTAssertEqual(updated.groups[0].gid, 701)
        XCTAssertFalse(updated.groups[0].createdByTool)
        XCTAssertEqual(updated.directories[0].inode, 2)
    }

    func testInteractiveSecurityRejectsInvalidInput() throws {
        let secret = String(repeating: "a", count: 32)
        for invalid in ["short", String(repeating: "a", count: 129), secret + "\nquit", secret + "'", secret + " "] {
            XCTAssertThrowsError(try SecurityCommandBuilder.createKeychain(keychainPath: "/tmp/test.keychain-db", password: invalid, expectedDirectory: "/tmp"))
        }
        for path in ["/other/test.keychain-db", "/tmp/../test.keychain-db", "/tmp/test keychain", "/tmp/test\nquit"] {
            XCTAssertThrowsError(try SecurityCommandBuilder.unlockKeychain(keychainPath: path, password: secret, expectedDirectory: "/tmp"))
        }
        let command = try SecurityCommandBuilder.createKeychain(keychainPath: "/tmp/test.keychain-db", password: secret, expectedDirectory: "/tmp")
        let expected = "create-keychain -p " + secret + " /tmp/test.keychain-db\n"
        XCTAssertTrue(command.stdinData == Data(expected.utf8))
        let generated = try SecurityCommandBuilder.generatePassword()
        XCTAssertEqual(generated.utf8.count, 64)
        XCTAssertNoThrow(try SecurityCommandBuilder.validatePassword(generated))
    }

    func testManifestDestroyAndReprovision() {
        let group = PrototypeGroupRecord(name: "test", gid: 700, createdByTool: true)
        let dir = PrototypeDirectoryRecord(path: "/tmp/test", inode: 1, ownerUid: 0)
        let provisioned = PrototypeManifest().addingGroup(group).addingCreatedDirectory(dir)
        let retained = provisioned.retainingExistingResources(groupGids: ["test": 701], directoryObservations: [dir.path: PrototypeDirectoryObservation(inode: 2, ownerUid: 0, isDirectory: true)])
        XCTAssertTrue(retained.isEmpty)
        let destroyed = provisioned.removingGroup(named: group.name).removingDirectory(at: dir.path)
        XCTAssertTrue(destroyed.isEmpty)
        XCTAssertEqual(destroyed.addingGroup(group).addingCreatedDirectory(dir), provisioned)
    }

    func testProcessRunnerHandlesClosedStdinAndTimeout() throws {
        XCTAssertThrowsError(try ProcessRunner.run(CommandSpec(executable: "/usr/bin/true", arguments: [], stdinData: Data(repeating: 97, count: 1024 * 1024))))
        let result = try ProcessRunner.runWithTimeout(CommandSpec(executable: "/bin/sleep", arguments: ["3"]), timeoutSeconds: 0.2)
        XCTAssertTrue(result.timedOut)
        XCTAssertFalse(result.succeeded)
    }

    func testManifestValidationPreservesObservationFailures() throws {
        enum ObservationError: Error { case denied }
        let manifest = PrototypeManifest(groups: [PrototypeGroupRecord(name: "test", gid: 700, createdByTool: true)], directories: [PrototypeDirectoryRecord(path: "/tmp/test", inode: 1, ownerUid: 0)])
        XCTAssertThrowsError(try manifest.observingExistingResources(groupGid: { _ in throw ObservationError.denied }, directoryObservation: { _ in nil }))
        XCTAssertThrowsError(try manifest.observingExistingResources(groupGid: { _ in 700 }, directoryObservation: { _ in throw ObservationError.denied }))
        let absent = try manifest.observingExistingResources(groupGid: { _ in nil }, directoryObservation: { _ in nil })
        XCTAssertTrue(absent.isEmpty)
        XCTAssertEqual(PrototypeCleanupEvaluator.groupDecision(manifest: manifest, groupName: "test", currentGid: nil), .alreadyAbsent)
        XCTAssertEqual(PrototypeCleanupEvaluator.directoryDecision(manifest: manifest, path: "/tmp/test", current: nil), .alreadyAbsent)
    }

    func testKeychainDirectoryPreparesOwnedFixture() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("atomium-keychain-dir-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try BoxKeychainDirectory.prepare(homeDirectory: root.path, uid: getuid(), gid: getgid())
        let keychain = root.appendingPathComponent("Library/Keychains/login.keychain-db")
        try Data("fixture".utf8).write(to: keychain)
        try BoxKeychainDirectory.prepare(homeDirectory: root.path, uid: getuid(), gid: getgid())
        XCTAssertFalse(FileManager.default.fileExists(atPath: keychain.path))
        for component in [".tmp", "Library", "Library/Keychains"] {
            let attributes = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent(component).path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
            XCTAssertEqual((attributes[.ownerAccountID] as? NSNumber)?.uint32Value, getuid())
        }
    }

    func testKeychainDirectoryRejectsSymlinkComponentsInOwnedFixture() throws {
        let fm = FileManager.default
        for component in ["home", ".tmp", "Library", "Library/Keychains"] {
            let root = fm.temporaryDirectory.appendingPathComponent("atomium-keychain-links-" + UUID().uuidString)
            try fm.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? fm.removeItem(at: root) }
            let target = root.appendingPathComponent("fixture-target")
            try fm.createDirectory(at: target, withIntermediateDirectories: true)
            let home = root.appendingPathComponent("home")
            if component != "home" { try fm.createDirectory(at: home, withIntermediateDirectories: true) }
            let link = component == "home" ? home : home.appendingPathComponent(component)
            try fm.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
            try fm.createSymbolicLink(at: link, withDestinationURL: target)
            XCTAssertThrowsError(try BoxKeychainDirectory.prepare(homeDirectory: home.path, uid: getuid(), gid: getgid()))
        }
    }

}
