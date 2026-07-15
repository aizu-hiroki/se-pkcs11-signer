import Foundation
import SEBlob

// se-pkcs11-signer-keygen — create / inspect Secure Enclave keys stored as blob files.
// No keychain, no entitlement, no provisioning profile. Each key is one
// `<label>.sekey` file in the key directory that the dylib reads.

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data(("error: " + msg + "\n").utf8))
    exit(1)
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

struct Args {
    var values: [String: [String]] = [:]
    var boolFlags: Set<String> = []
    init(_ argv: ArraySlice<String>) {
        var it = argv.makeIterator()
        while let a = it.next() {
            guard a.hasPrefix("--") else { fail("unexpected argument: \(a)") }
            let key = String(a.dropFirst(2))
            if key == "require-biometry" {
                boolFlags.insert(key)
            } else {
                guard let v = it.next() else { fail("missing value for --\(key)") }
                values[key, default: []].append(v)
            }
        }
    }
    func first(_ k: String) -> String? { values[k]?.last }     // last wins for single-value flags
    func all(_ k: String) -> [String] { values[k] ?? [] }      // repeatable flags
    func require(_ k: String) -> String {
        guard let v = first(k) else { fail("missing required --\(k)") }
        return v
    }
    func dir() -> String { first("dir") ?? SEBlob.defaultKeyDir }
}

func path(_ dir: String, _ label: String) -> String { "\(dir)/\(label).sekey" }

func cmdCreate(_ args: Args) {
    let label = args.require("label")
    let dir = args.dir()
    if label.contains("/") { fail("label must not contain '/'") }
    do {
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let info = try SEBlob.create(label: label, requireBiometry: args.boolFlags.contains("require-biometry"))
        let file = path(dir, label)
        if FileManager.default.fileExists(atPath: file) { fail("key already exists: \(file)") }
        try info.blob.write(to: URL(fileURLWithPath: file))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file)
        print("created Secure Enclave key -> \(file)")
        print("CKA_LABEL    : \(info.label)")
        print("CKA_ID (hex) : \(hex(info.id))")
        print("public key   : \(hex(info.publicKey))  (uncompressed EC point, \(info.publicKey.count) bytes)")
    } catch { fail("\(error)") }
}

func cmdList(_ args: Args) {
    let dir = args.dir()
    let entries = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    let keys = entries.filter { $0.hasSuffix(".sekey") }.sorted()
    if keys.isEmpty { print("(no keys in \(dir))"); return }
    print("keys in \(dir):")
    for name in keys {
        let label = String(name.dropLast(".sekey".count))
        guard let blob = FileManager.default.contents(atPath: "\(dir)/\(name)"),
              let info = try? SEBlob.info(label: label, blob: blob) else {
            print("  \(label): (unreadable)"); continue
        }
        print("  \(label): id=\(hex(info.id))")
    }
}

func cmdDelete(_ args: Args) {
    let file = path(args.dir(), args.require("label"))
    guard FileManager.default.fileExists(atPath: file) else { fail("no such key: \(file)") }
    do { try FileManager.default.removeItem(atPath: file); print("deleted \(file)") }
    catch { fail("\(error)") }
}

let usage = """
usage:
  se-pkcs11-signer-keygen create --label <label> [--dir <keydir>] [--require-biometry]
  se-pkcs11-signer-keygen list   [--dir <keydir>]
  se-pkcs11-signer-keygen delete --label <label> [--dir <keydir>]
  se-pkcs11-signer-keygen csr    --label <label> [--dir <keydir>] [--cn <name>]
                          [--uri <uri>]... [--dns <name>]... [--out <file>]

notes:
  * creates EC P-256 keys in the Secure Enclave, stored as <label>.sekey blob
    files (default dir: \(SEBlob.defaultKeyDir); override with --dir or
    SE_PKCS11_SIGNER_KEY_DIR). The dylib reads the same directory.
  * --label maps to PKCS#11 CKA_LABEL; the printed CKA_ID (hex) maps to CKA_ID.
    use these in the spire plugin's key_label / key_id.
  * csr emits a PKCS#10 CSR signed by the Secure Enclave key (proof of
    possession). --uri / --dns are repeatable Subject Alternative Names; --uri
    is a URI SAN (e.g. spiffe://trust-domain/node). Hand the CSR to your CA to
    get a certificate, then point the spire plugin's certificate_path at it.
  * no keychain / entitlement / provisioning profile required. Protect the
    .sekey files: anyone who can read one can ask the Secure Enclave to sign
    with it (the private key itself stays non-exportable inside the SE).
"""

let argv = CommandLine.arguments.dropFirst()
guard let sub = argv.first else { print(usage); exit(2) }
let rest = Args(argv.dropFirst())
switch sub {
case "create": cmdCreate(rest)
case "list":   cmdList(rest)
case "delete": cmdDelete(rest)
case "csr":    cmdCSR(rest)
case "-h", "--help", "help": print(usage)
default: fail("unknown subcommand: \(sub)\n\n\(usage)")
}
