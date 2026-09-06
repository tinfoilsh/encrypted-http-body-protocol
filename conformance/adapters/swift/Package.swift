// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "EHBPAdapter",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../../..")
    ],
    targets: [
        .executableTarget(
            name: "ehbp-adapter",
            dependencies: [.product(name: "EHBP", package: "encrypted-http-body-protocol")]
        )
    ]
)
