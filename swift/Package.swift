// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "EHBP",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .tvOS(.v17),
        .watchOS(.v10)
    ],
    products: [
        .library(
            name: "EHBP",
            targets: ["EHBP"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "EHBP",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(
            name: "EHBPTests",
            dependencies: ["EHBP"]
        )
    ]
)
