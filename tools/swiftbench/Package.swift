// swift-tools-version: 5.9
import PackageDescription

// swiftbench is a standalone package rather than an executable target inside the
// Swift library, for the same reason gobench is a standalone module rather than a
// tool in the Go repo: a benchmark harness is not part of either library's public
// surface. Adding an executable product to Scionic-MerkleTree-Swift would ship a
// `swiftbench` binary to every consumer of that package.
let package = Package(
    name: "swiftbench",
    platforms: [
        // Must not exceed the library's floor; it declares .macOS(.v12).
        .macOS(.v12),
    ],
    products: [
        .executable(name: "swiftbench", targets: ["swiftbench"]),
    ],
    dependencies: [
        // This path describes the working tree, not a published release.
        .package(path: "../../../Scionic-MerkleTree-Swift"),
    ],
    targets: [
        .executableTarget(
            name: "swiftbench",
            // The package is addressed by SwiftPM identity, which for a path
            // dependency is the directory's basename (matched case-insensitively),
            // NOT the `name:` the dependency's own manifest declares -- that is
            // "ScionicMerkleTree" here and does not resolve. The bare-string form
            // does not resolve either.
            dependencies: [
                .product(name: "ScionicMerkleTree", package: "Scionic-MerkleTree-Swift")
            ],
            path: "src"
        ),
    ]
)
