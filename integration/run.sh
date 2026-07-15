#!/usr/bin/env bash
# Build the se-pkcs11-signer dylib + keygen and run the SPIRE plugin integration test
# against a real macOS Secure Enclave key. macOS + Apple Silicon only.
#
# The SPIRE plugin is pulled in via the `replace` directive in go.mod, so its
# repository is not modified. Default location: ../../spire-plugin-node-attestor-x509pop-pkcs11
set -euo pipefail

cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"

echo "building se-pkcs11-signer..."
( cd "$REPO" && swift build -c release )

export SE_PKCS11_SIGNER_DYLIB="$REPO/.build/release/libse-pkcs11-signer.dylib"
export SE_PKCS11_SIGNER_KEYGEN="$REPO/.build/release/se-pkcs11-signer-keygen"

go test ./... -v
