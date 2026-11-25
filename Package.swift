// swift-tools-version:5.9
import PackageDescription

// EHBPCore is the verified Dafny core behind a C ABI (rust/ffi), packaged as
// an xcframework by swift/build-core.sh; run it before building. Release
// builds attach the xcframework to the GitHub release and pin its checksum
// here (conformance/spec/swift-ffi.md).
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
    targets: [
        .binaryTarget(
            name: "EHBPCore",
            path: "swift/EHBPCore.xcframework"
        ),
        .target(
            name: "EHBP",
            dependencies: ["EHBPCore"],
            path: "swift/Sources/EHBP"
        ),
        .testTarget(
            name: "EHBPTests",
            dependencies: ["EHBP"],
            path: "swift/Tests/EHBPTests"
        )
    ]
)
