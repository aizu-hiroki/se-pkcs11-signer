import CCryptoki
import Foundation
import SEBlob

struct Pkcs11Object {
    let handle: CK_ULONG
    let classValue: CK_ULONG // CKO_*
    let id: Data
    let label: String
    let keyType: CK_ULONG? // CKK_*, key objects only
    let ecParams: Data? // DER OID, EC keys only
    let ecPoint: Data? // DER-wrapped uncompressed point, public keys only
    let blob: Data? // SE key blob, private-key objects only (used to sign)
}

/// PKCS#11 object view built from `*.sekey` blob files in the key directory.
/// Each key becomes a matching CKO_PRIVATE_KEY + CKO_PUBLIC_KEY pair sharing
/// one CKA_ID / CKA_LABEL.
final class ObjectCatalog {
    let objects: [Pkcs11Object]

    private init(objects: [Pkcs11Object]) {
        self.objects = objects
    }

    static func load() -> ObjectCatalog {
        let dir = Config.keyDir
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: dir) else {
            return ObjectCatalog(objects: [])
        }

        var result: [Pkcs11Object] = []
        var nextHandle: CK_ULONG = 1

        for name in entries.sorted() where name.hasSuffix(".sekey") {
            guard let blob = fm.contents(atPath: "\(dir)/\(name)") else { continue }
            let label = String(name.dropLast(".sekey".count))
            guard let info = try? SEBlob.info(label: label, blob: blob) else { continue }

            let privHandle = nextHandle; nextHandle += 1
            result.append(Pkcs11Object(
                handle: privHandle,
                classValue: CK_ULONG(CKO_PRIVATE_KEY),
                id: info.id,
                label: label,
                keyType: CK_ULONG(CKK_EC),
                ecParams: ASN1.secp256r1OID,
                ecPoint: nil,
                blob: blob
            ))

            let pubHandle = nextHandle; nextHandle += 1
            result.append(Pkcs11Object(
                handle: pubHandle,
                classValue: CK_ULONG(CKO_PUBLIC_KEY),
                id: info.id,
                label: label,
                keyType: CK_ULONG(CKK_EC),
                ecParams: ASN1.secp256r1OID,
                ecPoint: ASN1.wrapOctetString(info.publicKey),
                blob: nil
            ))
        }

        return ObjectCatalog(objects: result)
    }
}
