# se-pkcs11-signer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Swift](https://img.shields.io/badge/Swift-5.9+-F05138.svg)](Package.swift)
[![Platform](https://img.shields.io/badge/platform-macOS%2012+-lightgrey.svg)](Package.swift)

> **⚠️ EXPERIMENTAL — USE AT YOUR OWN RISK**
>
> This project is experimental and provided "as-is" without any warranty or
> guarantee of any kind. It has not been audited for security and is not
> intended for production use. The authors and contributors accept no
> responsibility or liability for any damages, data loss, security incidents,
> or other consequences arising from the use of this software. **You use this
> software entirely at your own risk.**

> This is an **unofficial** community project and is not affiliated with or
> endorsed by SPIFFE, SPIRE, the CNCF, or Apple.

---

A macOS dylib that exposes a **Secure Enclave-backed private key through a
minimal PKCS#11-shaped C ABI**, plus a CLI to create the key and its CSR. It
exists to pair with
[spire-plugin-node-attestor-x509pop-pkcs11](https://github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11)'s
`x509pop_pkcs11` node attestor, giving a SPIRE agent a hardware-backed node
identity on Macs — the same role a TPM or external HSM plays on other
platforms.

The key is stored as a CryptoKit "data representation" blob file, **not in
the keychain**. That means no `keychain-access-groups` entitlement, no
provisioning profile, and no Apple Developer account are required — an
ad-hoc signed binary (the Swift/Go default) can sign with the Secure Enclave
key as-is.

The private key never leaves the Secure Enclave. The blob is a wrapper the
SE encrypted with a device-unique hardware key; it can only be decrypted and
used on the device that created it.

## Not a general-purpose PKCS#11 module

This dylib implements **only the 14 PKCS#11 functions its one intended
consumer calls** — it does not implement `C_GetFunctionList` (the standard
bootstrap every generic PKCS#11 consumer relies on), `C_Verify`,
`C_GenerateKeyPair`, `C_Encrypt`/`C_Decrypt`, or most of the rest of the
PKCS#11 v2.40 surface. It will not work as a drop-in module for
`pkcs11-tool`, OpenSSL's PKCS#11 engine/provider, browsers, or any other
generic PKCS#11 consumer. See [Implemented PKCS#11 functions](#implemented-pkcs11-functions)
below for the exact list and rationale.

## How it fits together

```
SPIRE agent (ad-hoc signed)                  key directory
  libse-pkcs11-signer.dylib  ──reads──▶  ~/.se-pkcs11-signer/keys/<label>.sekey (SE blob, 0600)
   PKCS#11 C ABI / in-process signing
```

- **libse-pkcs11-signer.dylib** — provides the PKCS#11 C ABI. `C_Initialize`
  reads `*.sekey` files from the key directory; `C_Sign` restores the SE key
  from its blob and signs (all in-process, in the caller's address space).
- **se-pkcs11-signer-keygen** — CLI that creates the SE key and writes the
  blob file, and emits a CSR signed by that key.

## Implemented PKCS#11 functions

Only what the consumer (`internal/pkcs11` in the sibling plugin, which
resolves symbols directly via `dlsym`/purego and never calls
`C_GetFunctionList`) actually calls:

- `C_Initialize` / `C_Finalize`
- `C_GetSlotList` / `C_GetTokenInfo`
- `C_OpenSession` / `C_CloseSession`
- `C_Login` / `C_Logout` (the PIN value itself is not verified — Secure
  Enclave keys are gated by the system's own Touch ID / passcode prompt, not
  a PIN this module knows)
- `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal`
- `C_GetAttributeValue`
- `C_SignInit` / `C_Sign` (`CKM_ECDSA` only; input is a SHA-256 digest,
  output is a raw `r||s` — 64 bytes, P-256. DER encoding is the caller's
  responsibility)

There is always exactly one slot (slot ID `0`). Each key is exposed as a
`CKO_PRIVATE_KEY` paired with a `CKO_PUBLIC_KEY`, sharing the same `CKA_ID`
(SHA-256 of the public key) and `CKA_LABEL` (the `.sekey` filename minus its
extension). `CKK_EC` only — Secure Enclave supports P-256 exclusively.

## Requirements

| Component | Version |
|-----------|---------|
| macOS     | 12+     |
| Hardware  | Apple Silicon (Secure Enclave) |
| Swift     | 5.9+    |

## Building

```sh
make          # shows available targets
make build    # swift build -c release
make symbols  # list the dylib's exported C_* PKCS#11 symbols
```

Building the `csr` command in the keygen CLI pulls in
[swift-certificates](https://github.com/apple/swift-certificates), so the
first build takes longer while dependencies resolve and compile. The dylib
itself does not depend on it.

No code signing is required — ad-hoc signing (the Swift/Go default) is
sufficient.

## Enrolling a node

```
keygen create → SE key + public key
keygen csr    → CSR signed by the SE key (with SAN)  ──▶ your CA signs it
                                                          ──▶ certificate PEM
spire plugin  ← certificate_path points at the certificate
```

`make` walks through this interactively:

```sh
make install       # copy the built dylib to a system location (sudo)
make csr           # create the SE key (if needed) and emit a CSR
#   ... hand the CSR to your CA ...
make install-cert  # install the CA-issued certificate, then print the
                    # spire agent plugin_data block
```

Or drive `se-pkcs11-signer-keygen` directly:

```sh
se-pkcs11-signer-keygen create --label my-node-key
# => <keydir>/my-node-key.sekey — prints CKA_LABEL / CKA_ID(hex) / public key
#    use CKA_ID / CKA_LABEL as the spire plugin's key_id / key_label

se-pkcs11-signer-keygen csr --label my-node-key \
    --cn  "node1.example.org" \
    --uri "spiffe://example.org/node/node1" \   # URI SAN (repeatable)
    --dns "node1.example.org" \                  # DNS SAN (repeatable)
    --out node1.csr

se-pkcs11-signer-keygen list
se-pkcs11-signer-keygen delete --label my-node-key
```

The key directory defaults to `~/.se-pkcs11-signer/keys` (override with
`--dir` or `SE_PKCS11_SIGNER_KEY_DIR` — keep the dylib and CLI pointed at the
same directory). `--require-biometry` requires Touch ID at signing time
(usually left off for unattended/daemon use).

## SPIRE agent configuration

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd  = "/usr/local/bin/spire-plugin-pkcs11-agent"
  plugin_data {
    module_path      = "/usr/local/lib/se-pkcs11-signer/libse-pkcs11-signer.dylib"
    token_label      = "Secure Enclave"
    key_id           = "<CKA_ID from keygen create>"
    key_label        = "my-node-key"
    certificate_path = "/path/to/node-cert.pem"
  }
}
```

## Configuration (environment variables)

| Variable | Read by | Purpose |
|---|---|---|
| `SE_PKCS11_SIGNER_KEY_DIR` | dylib / keygen | directory holding `.sekey` files (default `~/.se-pkcs11-signer/keys`) |
| `SE_PKCS11_SIGNER_TOKEN_LABEL` | dylib | `CK_TOKEN_INFO.label` (default `Secure Enclave`) |
| `SE_PKCS11_SIGNER_MANUFACTURER` | dylib | `CK_TOKEN_INFO.manufacturerID` (default `Apple`) |

## Security notes

- Anyone who can read a `.sekey` blob can ask the Secure Enclave to **sign**
  with that key (the private key itself cannot be extracted from the SE).
  Protect the files with `0600` and lock down the key directory's
  permissions.
- A blob is only usable on the Secure Enclave of the device that created
  it. Moving it to another machine does not let that machine recover or use
  the key — there is no backup path by design.
- The location where you install the dylib (`make install`'s target
  directory) should not be writable by unprivileged users: whoever can
  replace it controls what gets signed with the Secure Enclave key.

## Known limitations

- EC P-256 only (a Secure Enclave constraint) — no RSA, no other curves.
- No `CKO_CERTIFICATE` objects — certificates are handed to the SPIRE plugin
  via `certificate_path` (PEM), not stored on the "token".
- Keys are enumerated once, at `C_Initialize`. A key created after the
  consuming process started won't be visible until it restarts.
- `C_GetFunctionList` is not implemented (see
  [Not a general-purpose PKCS#11 module](#not-a-general-purpose-pkcs11-module)
  above).

## License

[Apache 2.0](LICENSE)
