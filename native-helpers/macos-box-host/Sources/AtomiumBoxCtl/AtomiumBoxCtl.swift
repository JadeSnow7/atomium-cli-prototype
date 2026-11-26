import BoxCore
import Foundation

@main
struct AtomiumBoxCtl {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let subcommand = args.first else {
            printUsage()
            exit(0)
        }
        let rest = Array(args.dropFirst())

        do {
            switch subcommand {
            case "--help", "-h", "help":
                printUsage()
            case "provision":
                try runProvision(rest)
            case "list":
                try runList(rest)
            case "destroy":
                try runDestroy(rest)
            case "prepare-app":
                try runPrepareApp(rest)
            case "launch":
                try runLaunch(rest)
            case "exec":
                let code = try runExec(rest)
                exit(code)
            case "report":
                try runReport(rest)
            case "keychain-init":
                try runKeychainInit(rest)
            case "give-file":
                try runGiveFile(rest)
            case "probe":
                try runProbe(rest)
            default:
                fputs("Unknown subcommand: \(subcommand)\n", stderr)
                printUsage()
                exit(2)
            }
        } catch {
            fputs("Error: \(error)\n", stderr)
            exit(1)
        }
    }

    static func runProvision(_ args: [String]) throws {
        guard let boxId = args.first, !boxId.hasPrefix("-") else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl provision <box_id>")
        }
        let evidence = try BoxLifecycle.provision(boxId: boxId)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(evidence)
        print(String(decoding: data, as: UTF8.self))
    }

    static func runList(_ args: [String]) throws {
        let asJson = args.contains("--json")
        let records = try BoxLifecycle.listPrefixedAccounts()
        if asJson {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            let data = try encoder.encode(records)
            print(String(decoding: data, as: UTF8.self))
            return
        }
        if records.isEmpty {
            print("No atombox_* accounts found.")
            return
        }
        print("SHORT_NAME\tUID\tGID\tHIDDEN\tMANAGED\tCOMMENT")
        for r in records {
            let uid = r.uid.map(String.init) ?? "-"
            let gid = r.primaryGid.map(String.init) ?? "-"
            let hidden = r.isHidden ?? "-"
            let managed = r.managed ? "yes" : "NO (\(r.validationError ?? "invalid"))"
            let comment = r.comment ?? "<none>"
            print("\(r.shortName)\t\(uid)\t\(gid)\t\(hidden)\t\(managed)\t\(comment)")
        }
    }

    static func runDestroy(_ args: [String]) throws {
        var boxId: String?
        var targetUser: String?
        var allPrototype = false
        var apply = false

        var idx = 0
        while idx < args.count {
            let token = args[idx]
            switch token {
            case "--all-prototype":
                allPrototype = true
            case "--apply":
                apply = true
            case "--dry-run":
                apply = false
            case "--target-user":
                idx += 1
                guard idx < args.count else {
                    throw BoxCLIError.invalidArguments("--target-user requires a short name")
                }
                targetUser = args[idx]
            default:
                if token.hasPrefix("-") {
                    throw BoxCLIError.invalidArguments("Unknown option: \(token)")
                }
                if boxId != nil {
                    throw BoxCLIError.invalidArguments("Unexpected extra argument: \(token)")
                }
                boxId = token
            }
            idx += 1
        }

        try BoxLifecycle.destroy(
            boxId: boxId,
            rawTargetUser: targetUser,
            allPrototype: allPrototype,
            apply: apply
        )
    }

    static func runPrepareApp(_ args: [String]) throws {
        guard let boxId = args.first, !boxId.hasPrefix("-") else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl prepare-app <box_id> --source <app_path> [--strip-quarantine]")
        }
        var sourcePath: String?
        var stripQuarantine = false
        var idx = 1
        while idx < args.count {
            switch args[idx] {
            case "--source":
                idx += 1
                guard idx < args.count else {
                    throw BoxCLIError.invalidArguments("--source requires an .app path")
                }
                sourcePath = args[idx]
            case "--strip-quarantine":
                stripQuarantine = true
            default:
                throw BoxCLIError.invalidArguments("Unknown option for prepare-app: \(args[idx])")
            }
            idx += 1
        }
        guard let sourcePath else {
            throw BoxCLIError.invalidArguments("prepare-app requires --source <app_path>")
        }
        let report = try BoxLauncher.prepareApp(boxId: boxId, sourceAppPath: sourcePath, stripQuarantine: stripQuarantine)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        print(String(decoding: try encoder.encode(report), as: UTF8.self))
    }

    static func runLaunch(_ args: [String]) throws {
        guard let boxId = args.first, !boxId.hasPrefix("-") else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl launch <box_id> --app <path> --variant <V1|V2|V3|V4> [--wait <sec>] [--sbpl <path>] [-- <args...>]")
        }
        var appPath: String?
        var variant: LaunchVariant?
        var waitSeconds: Double = 3.0
        var sbplProfile: String?
        var extraArgs: [String] = []

        var idx = 1
        while idx < args.count {
            let token = args[idx]
            if token == "--" {
                extraArgs = Array(args[(idx + 1)...])
                break
            }
            switch token {
            case "--app":
                idx += 1
                guard idx < args.count else { throw BoxCLIError.invalidArguments("--app requires a path") }
                appPath = args[idx]
            case "--variant":
                idx += 1
                guard idx < args.count, let parsed = LaunchVariant(rawValue: args[idx].uppercased()) else {
                    throw BoxCLIError.invalidArguments("--variant must be V1, V2, V3, or V4")
                }
                variant = parsed
            case "--wait":
                idx += 1
                guard idx < args.count, let secs = Double(args[idx]) else {
                    throw BoxCLIError.invalidArguments("--wait requires a number of seconds")
                }
                waitSeconds = secs
            case "--sbpl":
                idx += 1
                guard idx < args.count else { throw BoxCLIError.invalidArguments("--sbpl requires a profile path") }
                sbplProfile = args[idx]
            default:
                throw BoxCLIError.invalidArguments("Unknown option for launch: \(token)")
            }
            idx += 1
        }

        guard let appPath, let variant else {
            throw BoxCLIError.invalidArguments("launch requires --app <path> and --variant <V1|V2|V3|V4>")
        }
        let report = try BoxLauncher.launch(
            boxId: boxId,
            appPath: appPath,
            variant: variant,
            waitSeconds: waitSeconds,
            sbplProfile: sbplProfile,
            extraArgs: extraArgs
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        print(String(decoding: try encoder.encode(report), as: UTF8.self))
    }

    static func runExec(_ args: [String]) throws -> Int32 {
        guard let boxId = args.first, !boxId.hasPrefix("-") else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl exec <box_id> [--asuser] -- <cmd...>")
        }
        var useAsuser = false
        var cmd: [String] = []
        var idx = 1
        while idx < args.count {
            if args[idx] == "--" {
                cmd = Array(args[(idx + 1)...])
                break
            } else if args[idx] == "--asuser" {
                useAsuser = true
            } else {
                throw BoxCLIError.invalidArguments("Unknown option for exec: \(args[idx])")
            }
            idx += 1
        }
        return try BoxLauncher.execCommand(boxId: boxId, useAsuser: useAsuser, command: cmd)
    }

    static func runReport(_ args: [String]) throws {
        var inputPath: String?
        var outDir: String?
        var idx = 0
        while idx < args.count {
            switch args[idx] {
            case "--input":
                idx += 1
                guard idx < args.count else {
                    throw BoxCLIError.invalidArguments("--input requires a path")
                }
                inputPath = args[idx]
            case "--out":
                idx += 1
                guard idx < args.count else {
                    throw BoxCLIError.invalidArguments("--out requires a directory path")
                }
                outDir = args[idx]
            default:
                throw BoxCLIError.invalidArguments("Unknown option for report: \(args[idx])")
            }
            idx += 1
        }
        guard let inputPath, let outDir else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl report --input <evidence.json> --out <dir>")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: inputPath))
        let doc = try EvidenceCodec.decode(data)
        let fm = FileManager.default
        try fm.createDirectory(atPath: outDir, withIntermediateDirectories: true)
        let normalizedData = try EvidenceCodec.encode(doc)
        let outEvidence = (outDir as NSString).appendingPathComponent("evidence.json")
        let outReport = (outDir as NSString).appendingPathComponent("report.md")
        try normalizedData.write(to: URL(fileURLWithPath: outEvidence))
        let markdown = EvidenceCodec.renderMarkdownReport(doc)
        try Data(markdown.utf8).write(to: URL(fileURLWithPath: outReport))
        print("Wrote \(outEvidence) and \(outReport)")
    }

    static func runKeychainInit(_ args: [String]) throws {
        guard let boxId = args.first, !boxId.hasPrefix("-") else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl keychain-init <box_id>")
        }
        let report = try BoxExtras.keychainInit(boxId: boxId)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        print(String(decoding: try encoder.encode(report), as: UTF8.self))
    }

    static func runGiveFile(_ args: [String]) throws {
        guard args.count == 2, !args[0].hasPrefix("-"), !args[1].hasPrefix("-") else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl give-file <box_id> <host_path>")
        }
        let report = try BoxExtras.giveFile(boxId: args[0], hostPath: args[1])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        print(String(decoding: try encoder.encode(report), as: UTF8.self))
    }

    static func runProbe(_ args: [String]) throws {
        guard let boxId = args.first, !boxId.hasPrefix("-") else {
            throw BoxCLIError.invalidArguments("Usage: atomium-boxctl probe <box_id> [--peer-box <peer_id>] [--clipboard-marker <token>]")
        }
        var peerBoxId: String?
        var clipboardMarker: String?
        var idx = 1
        while idx < args.count {
            switch args[idx] {
            case "--peer-box":
                idx += 1
                guard idx < args.count else { throw BoxCLIError.invalidArguments("--peer-box requires a box_id") }
                peerBoxId = args[idx]
            case "--clipboard-marker":
                idx += 1
                guard idx < args.count else { throw BoxCLIError.invalidArguments("--clipboard-marker requires a token") }
                clipboardMarker = args[idx]
            default:
                throw BoxCLIError.invalidArguments("Unknown option for probe: \(args[idx])")
            }
            idx += 1
        }
        let report = try BoxExtras.runFullProbe(boxId: boxId, peerBoxId: peerBoxId, clipboardMarker: clipboardMarker)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        print(String(decoding: try encoder.encode(report), as: UTF8.self))
    }

    static func printUsage() {
        print(
            """
            Usage: atomium-boxctl <subcommand> [options]

            Subcommands:
              provision <box_id>                     Provision an isolated hidden macOS Box user (requires root)
              destroy <box_id> [--apply]             Destroy managed Box user (dry-run by default)
              destroy --target-user <name> [--apply] Inspect/reject or destroy by raw short name (dry-run by default)
              destroy --all-prototype [--apply]      Destroy all managed prototype Box users & groups (dry-run by default)
              list [--json]                          List atombox_* accounts and guardrail status
              prepare-app <box_id> --source <app>    Copy .app into Box ~/Applications and verify signature
              launch <box_id> --app <path> --variant <V1|V2|V3|V4> [--wait <sec>] [--sbpl <path>]
                                                     Launch a GUI app inside a Box user
              exec <box_id> [--asuser] -- <cmd...>   Execute a command as a Box user
              keychain-init <box_id>                 Initialize Box user's login keychain
              give-file <box_id> <host_path>         Deliver a single file into Box Inbox (0600)
              probe <box_id>                         Run isolation probes inside Box
              report --input <evidence.json> --out <dir>
                                                     Generate report.md from evidence.json
            """
        )
    }
}
