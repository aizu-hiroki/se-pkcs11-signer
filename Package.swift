// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "se-pkcs11-signer",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "se-pkcs11-signer", type: .dynamic, targets: ["se-pkcs11-signer"]),
        .executable(name: "se-pkcs11-signer-keygen", targets: ["se-pkcs11-signer-keygen"])
    ],
    dependencies: [
        // Used only by the keygen CLI (csr command), not by the dylib.
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.19.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.0")
    ],
    targets: [
        .target(name: "CCryptoki"),
        // Secure Enclave key blobs (CryptoKit) + ASN.1 helpers.
        .target(name: "SEBlob"),
        // The PKCS#11 dylib. Reads *.sekey blob files and signs in-process.
        .target(name: "se-pkcs11-signer", dependencies: ["CCryptoki", "SEBlob"]),
        .executableTarget(
            name: "se-pkcs11-signer-keygen",
            dependencies: [
                "SEBlob",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        )
    ]
)
