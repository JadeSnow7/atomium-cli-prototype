// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AtomiumBoxHost",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "BoxCore", targets: ["BoxCore"]),
        .executable(name: "atomium-boxctl", targets: ["AtomiumBoxCtl"]),
        .executable(name: "atomium-box-agent", targets: ["AtomiumBoxAgent"]),
        .executable(name: "atomium-box-overlay", targets: ["AtomiumBoxOverlay"]),
        .executable(name: "atomium-box-clip", targets: ["AtomiumBoxClip"]),
        .executable(name: "atomium-box-probe", targets: ["AtomiumBoxProbe"]),
    ],
    targets: [
        .target(
            name: "BoxCore"
        ),
        .executableTarget(
            name: "AtomiumBoxCtl",
            dependencies: ["BoxCore"]
        ),
        .executableTarget(
            name: "AtomiumBoxAgent",
            dependencies: ["BoxCore"]
        ),
        .executableTarget(
            name: "AtomiumBoxOverlay",
            dependencies: ["BoxCore"]
        ),
        .executableTarget(
            name: "AtomiumBoxClip",
            dependencies: ["BoxCore"]
        ),
        .executableTarget(
            name: "AtomiumBoxProbe",
            dependencies: ["BoxCore"]
        ),
        .testTarget(
            name: "BoxCoreTests",
            dependencies: ["BoxCore"]
        ),
    ]
)
