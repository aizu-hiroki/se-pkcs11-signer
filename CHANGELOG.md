# Changelog

## [v0.1.0] - 2026-07-15

- Initial release.
- `libse-pkcs11-signer.dylib`: minimal PKCS#11-shaped C ABI over a Secure
  Enclave-backed EC P-256 key (`C_Initialize`/`C_Finalize`,
  `C_GetSlotList`/`C_GetTokenInfo`, `C_OpenSession`/`C_CloseSession`,
  `C_Login`/`C_Logout`, `C_FindObjects*`, `C_GetAttributeValue`,
  `C_SignInit`/`C_Sign` with `CKM_ECDSA`).
- `se-pkcs11-signer-keygen` CLI: `create`, `list`, `delete`, and `csr`
  (PKCS#10 CSR with SAN support, signed by the Secure Enclave key).
- Keys stored as CryptoKit "data representation" blob files — no keychain,
  no entitlement, no provisioning profile required.
- `Makefile` with interactive `install`, `csr`, `install-cert`, and
  `print-config` targets covering the full node enrollment flow.
- Verified end-to-end against a real Secure Enclave key together with the
  sibling [spire-plugin-node-attestor-x509pop-pkcs11](https://github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11)
  `x509pop_pkcs11` node attestor.
