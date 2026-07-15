import CryptoKit
import Foundation
import SEBlob
import SwiftASN1
import X509

// `se-pkcs11-signer-keygen csr` — emit a PKCS#10 CSR signed by a Secure Enclave key,
// with optional Subject Alternative Names (URI / DNS). The CSR signature is the
// proof of possession the CA relies on before issuing the leaf certificate.
func cmdCSR(_ args: Args) {
    let label = args.require("label")
    let file = "\(args.dir())/\(label).sekey"
    guard let blob = FileManager.default.contents(atPath: file) else {
        fail("no such key: \(file)")
    }

    let cn = args.first("cn") ?? label
    let uris = args.all("uri")
    let dnsNames = args.all("dns")

    do {
        let seKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        let privateKey = Certificate.PrivateKey(seKey)

        let subject = try DistinguishedName { CommonName(cn) }

        var attributes = CertificateSigningRequest.Attributes()
        if !uris.isEmpty || !dnsNames.isEmpty {
            var generalNames: [GeneralName] = []
            generalNames.append(contentsOf: uris.map { .uniformResourceIdentifier($0) })
            generalNames.append(contentsOf: dnsNames.map { .dnsName($0) })
            let san = SubjectAlternativeNames(generalNames)
            let extensions = try Certificate.Extensions([try Certificate.Extension(san, critical: false)])
            let attr = try CertificateSigningRequest.Attribute(ExtensionRequest(extensions: extensions))
            attributes = CertificateSigningRequest.Attributes([attr])
        }

        let csr = try CertificateSigningRequest(
            version: .v1,
            subject: subject,
            privateKey: privateKey,
            attributes: attributes,
            signatureAlgorithm: .ecdsaWithSHA256
        )

        let pem = try csr.serializeAsPEM().pemString
        let out = args.first("out") ?? "\(label).csr"
        try pem.write(toFile: out, atomically: true, encoding: .utf8)

        print("wrote CSR -> \(out)")
        print("  subject : CN=\(cn)")
        if !uris.isEmpty { print("  SAN URI : \(uris.joined(separator: ", "))") }
        if !dnsNames.isEmpty { print("  SAN DNS : \(dnsNames.joined(separator: ", "))") }
    } catch {
        fail("\(error)")
    }
}
