import Darwin
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
        try execute(spec, timeoutSeconds: nil, environment: environment, currentDirectoryPath: currentDirectoryPath)
    }

    public static func runWithTimeout(
        _ spec: CommandSpec,
        timeoutSeconds: Double = 5.0,
        environment: [String: String]? = nil,
        currentDirectoryPath: String? = nil
    ) throws -> ProcessResult {
        try execute(spec, timeoutSeconds: timeoutSeconds, environment: environment, currentDirectoryPath: currentDirectoryPath)
    }

    private static func execute(
        _ spec: CommandSpec,
        timeoutSeconds: Double?,
        environment: [String: String]?,
        currentDirectoryPath: String?
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
        let stdinPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        if spec.stdinData != nil {
            process.standardInput = stdinPipe
        }

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

        let inputError = OSAllocatedUnfairLock<Int32?>(initialState: nil)
        try process.run()
        if let stdinData = spec.stdinData {
            let input = stdinPipe.fileHandleForWriting
            // A child may close stdin before the write. Preserve EPIPE as an error
            // instead of allowing SIGPIPE to terminate the helper.
            guard fcntl(input.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
                process.terminate()
                throw ProcessRunnerError.stdinWriteFailed(errno)
            }
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave() }
                do {
                    defer { input.closeFile() }
                    try input.write(contentsOf: stdinData)
                } catch {
                    inputError.withLock { $0 = Int32((error as NSError).code) }
                }
            }
        }

        var timedOut = false
        if let timeoutSeconds {
            let deadline = Date().addingTimeInterval(max(0.2, timeoutSeconds))
            while process.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            timedOut = process.isRunning
        } else {
            process.waitUntilExit()
        }
        if timedOut {
            process.terminate()
            Thread.sleep(forTimeInterval: 0.1)
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
        }
        process.waitUntilExit()
        group.wait()
        if let code = inputError.withLock({ $0 }), !timedOut {
            throw ProcessRunnerError.stdinWriteFailed(code)
        }

        return ProcessResult(
            exitCode: timedOut ? -1 : process.terminationStatus,
            stdout: String(decoding: outBox.withLock { $0 }, as: UTF8.self),
            stderr: String(decoding: errBox.withLock { $0 }, as: UTF8.self),
            timedOut: timedOut
        )
    }
}

public enum ProcessRunnerError: Error {
    case stdinWriteFailed(Int32)
}
