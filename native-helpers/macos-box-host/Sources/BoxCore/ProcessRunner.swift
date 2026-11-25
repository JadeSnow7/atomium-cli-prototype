import Foundation
import os

public struct ProcessResult: Equatable, Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
    public let timedOut: Bool

    public init(exitCode: Int32, stdout: String, stderr: String, timedOut: Bool = false) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
    }

    public var succeeded: Bool {
        !timedOut && exitCode == 0
    }
}

public enum ProcessRunner {
    public static func run(
        _ spec: CommandSpec,
        environment: [String: String]? = nil,
        currentDirectoryPath: String? = nil
    ) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: spec.executable)
        process.arguments = spec.arguments
        if let environment {
            process.environment = environment
        }
        if let currentDirectoryPath {
            process.currentDirectoryURL = URL(fileURLWithPath: currentDirectoryPath, isDirectory: true)
        }

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let outBox = OSAllocatedUnfairLock(initialState: Data())
        let errBox = OSAllocatedUnfairLock(initialState: Data())
        let group = DispatchGroup()

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            outBox.withLock { $0 = data }
            group.leave()
        }

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            let data = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            errBox.withLock { $0 = data }
            group.leave()
        }

        try process.run()
        process.waitUntilExit()
        group.wait()

        return ProcessResult(
            exitCode: process.terminationStatus,
            stdout: String(decoding: outBox.withLock { $0 }, as: UTF8.self),
            stderr: String(decoding: errBox.withLock { $0 }, as: UTF8.self),
            timedOut: false
        )
    }

    public static func runWithTimeout(
        _ spec: CommandSpec,
        timeoutSeconds: Double = 5.0,
        environment: [String: String]? = nil,
        currentDirectoryPath: String? = nil
    ) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: spec.executable)
        process.arguments = spec.arguments
        if let environment {
            process.environment = environment
        }
        if let currentDirectoryPath {
            process.currentDirectoryURL = URL(fileURLWithPath: currentDirectoryPath, isDirectory: true)
        }

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let outBox = OSAllocatedUnfairLock(initialState: Data())
        let errBox = OSAllocatedUnfairLock(initialState: Data())
        let group = DispatchGroup()

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            outBox.withLock { $0 = data }
            group.leave()
        }

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            let data = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            errBox.withLock { $0 = data }
            group.leave()
        }

        try process.run()

        let deadline = Date().addingTimeInterval(max(0.2, timeoutSeconds))
        var timedOut = false
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning {
            timedOut = true
            process.terminate()
            Thread.sleep(forTimeInterval: 0.1)
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
        }
        _ = group.wait(timeout: .now() + 1.0)

        return ProcessResult(
            exitCode: timedOut ? -1 : process.terminationStatus,
            stdout: String(decoding: outBox.withLock { $0 }, as: UTF8.self),
            stderr: String(decoding: errBox.withLock { $0 }, as: UTF8.self),
            timedOut: timedOut
        )
    }
}
