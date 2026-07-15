import CryptoKit
import Foundation

// Secure Enclave keys stored as CryptoKit "data representation" blobs in files —
// no keychain, so no keychain-access-groups entitlement and no provisioning
// profile are required. The private key never leaves the Secure Enclave; the
// blob is an SE-encrypted wrapper usable only on the device that made it.

public struct SEKeyInfo {
    public let id: Data          // CKA_ID  = SHA-256 of the public key
    public let label: String     // CKA_LABEL
    public let publicKey: Data   // uncompressed X9.63 point 0x04||X||Y (65 bytes)
    public let blob: Data        // SE data representation (store this in a file)
}

public enum SEBlobError: Error, CustomStringConvertible {
    case message(String)
    public var description: String {
        if case let .message(m) = self { return m }
        return "SEBlob error"
    }
}

public enum SEBlob {
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public static var defaultKeyDir: String {
        if let d = ProcessInfo.processInfo.environment["SE_PKCS11_SIGNER_KEY_DIR"], !d.isEmpty { return d }
        return "\(NSHomeDirectory())/.se-pkcs11-signer/keys"
    }

    public static func create(label: String, requireBiometry: Bool) throws -> SEKeyInfo {
        guard SecureEnclave.isAvailable else {
            throw SEBlobError.message("Secure Enclave is not available on this machine")
        }
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireBiometry { flags.insert(.biometryAny) }
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, nil
        ) else { throw SEBlobError.message("could not create access control") }

        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        return info(label: label, key: key)
    }

    public static func info(label: String, blob: Data) throws -> SEKeyInfo {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        return info(label: label, key: key)
    }

    /// Raw ECDSA (CKM_ECDSA) over a caller-supplied 32-byte digest → raw r||s.
    public static func sign(blob: Data, digest: Data) throws -> Data {
        guard digest.count == RawDigest.byteCount else {
            throw SEBlobError.message("digest must be \(RawDigest.byteCount) bytes (SHA-256)")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        let signature = try key.signature(for: RawDigest(bytes: [UInt8](digest)))
        return signature.rawRepresentation
    }

    private static func info(label: String, key: SecureEnclave.P256.Signing.PrivateKey) -> SEKeyInfo {
        let pub = key.publicKey.x963Representation
        return SEKeyInfo(id: Data(SHA256.hash(data: pub)), label: label, publicKey: pub, blob: key.dataRepresentation)
    }
}

/// Lets a Secure Enclave key sign an externally-supplied digest (the bytes
/// C_Sign receives) rather than data CryptoKit would hash itself.
struct RawDigest: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    static func == (lhs: RawDigest, rhs: RawDigest) -> Bool { lhs.bytes == rhs.bytes }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    var description: String { "RawDigest(\(bytes.count) bytes)" }
}
