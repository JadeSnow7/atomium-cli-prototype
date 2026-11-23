// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AtomiumBrowserHost",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "atomium-browser-host", targets: ["AtomiumBrowserHost"])
    ],
    targets: [
        .executableTarget(name: "AtomiumBrowserHost")
    ]
)
