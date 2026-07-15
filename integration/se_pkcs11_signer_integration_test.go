// Integration test driving the SPIRE agent x509pop_pkcs11 plugin against the
// se-pkcs11-signer dylib backed by a real macOS Secure Enclave key.
//
// This is a standalone Go module that imports the plugin via a `replace`
// directive, so the plugin repository itself is not modified.
//
// Requires (set by run.sh):
//   SE_PKCS11_SIGNER_DYLIB   absolute path to libse-pkcs11-signer.dylib
//   SE_PKCS11_SIGNER_KEYGEN  absolute path to se-pkcs11-signer-keygen
//
// Run: ./run.sh   (or: go test ./... -v with the env vars set)
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/pkg/pkcs11attestor/agent"
	nodeattestoragentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// seStream is a minimal agent-side gRPC stream that hands back one challenge.
type seStream struct {
	nodeattestoragentv1.NodeAttestor_AidAttestationServer
	sent      []*nodeattestoragentv1.PayloadOrChallengeResponse
	challenge []byte
	recvIdx   int
}

func (s *seStream) Send(msg *nodeattestoragentv1.PayloadOrChallengeResponse) error {
	s.sent = append(s.sent, msg)
	return nil
}

func (s *seStream) Recv() (*nodeattestoragentv1.Challenge, error) {
	if s.recvIdx > 0 {
		return nil, context.Canceled
	}
	s.recvIdx++
	return &nodeattestoragentv1.Challenge{Challenge: s.challenge}, nil
}

func (s *seStream) Context() context.Context { return context.Background() }

func TestSEPKCS11Signer_FullAttestationFlow(t *testing.T) {
	dylib := os.Getenv("SE_PKCS11_SIGNER_DYLIB")
	keygen := os.Getenv("SE_PKCS11_SIGNER_KEYGEN")
	if dylib == "" || keygen == "" {
		t.Skip("SE_PKCS11_SIGNER_DYLIB / SE_PKCS11_SIGNER_KEYGEN not set (run via ./run.sh)")
	}

	// 1. Create a real Secure Enclave key via keygen (file-blob, no keychain).
	keyDir := t.TempDir()
	os.Setenv("SE_PKCS11_SIGNER_KEY_DIR", keyDir) // read by the dylib at C_Initialize
	const label = "node-key"

	out, err := exec.Command(keygen, "create", "--label", label, "--dir", keyDir).CombinedOutput()
	if err != nil {
		t.Fatalf("keygen create: %v\n%s", err, out)
	}
	keyIDHex := grab(t, out, `CKA_ID \(hex\) : ([0-9a-f]+)`)
	pubHex := grab(t, out, `public key   : (04[0-9a-f]+)`)
	t.Logf("Secure Enclave key created: id=%s", keyIDHex)

	// 2. Build the SE public key and issue a leaf cert for it, signed by a test CA.
	sePub := parseP256Point(t, pubHex)
	caCert, caKey := makeCA(t)
	leafDER := makeLeaf(t, sePub, caCert, caKey)
	certPath := filepath.Join(keyDir, "leaf.pem")
	writePEM(t, certPath, leafDER)

	// 3. Configure the agent plugin to use our dylib.
	plug := agent.New()
	t.Cleanup(plug.Close)
	hclConfig := `
		module_path      = "` + dylib + `"
		token_label      = "Secure Enclave"
		key_id           = "` + keyIDHex + `"
		key_label        = "` + label + `"
		certificate_path = "` + certPath + `"
	`
	if _, err := plug.Configure(context.Background(), &configv1.ConfigureRequest{HclConfiguration: hclConfig}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	// 4. Run attestation: the plugin signs the nonce with the Secure Enclave key.
	nonce := []byte("se-pkcs11-signer-integration-nonce-0001")
	stream := &seStream{challenge: nonce}
	if err := plug.AidAttestation(stream); err != nil {
		t.Fatalf("AidAttestation: %v", err)
	}
	if len(stream.sent) != 2 {
		t.Fatalf("expected 2 messages (payload + challenge response), got %d", len(stream.sent))
	}

	// 5. Act as the SPIRE server: verify the cert chain and the proof of possession.
	var payload struct {
		Certificates [][]byte `json:"certificates"`
	}
	if err := json.Unmarshal(stream.sent[0].GetPayload(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	leaf, err := x509.ParseCertificate(payload.Certificates[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("cert chain does not verify against test CA: %v", err)
	}

	var resp struct {
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(stream.sent[1].GetChallengeResponse(), &resp); err != nil {
		t.Fatalf("unmarshal challenge response: %v", err)
	}
	digest := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(leaf.PublicKey.(*ecdsa.PublicKey), digest[:], resp.Signature) {
		t.Fatal("proof-of-possession signature (from Secure Enclave) failed to verify against leaf cert")
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(sePub) {
		t.Fatal("leaf public key does not match the Secure Enclave key")
	}
	t.Log("full x509pop_pkcs11 attestation verified with a real Secure Enclave key")

	_, _ = exec.Command(keygen, "delete", "--label", label, "--dir", keyDir).CombinedOutput()
}

func grab(t *testing.T, out []byte, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindSubmatch(out)
	if m == nil {
		t.Fatalf("could not find %q in keygen output:\n%s", pattern, out)
	}
	return string(m[1])
}

func parseP256Point(t *testing.T, pointHex string) *ecdsa.PublicKey {
	t.Helper()
	pt, err := hex.DecodeString(pointHex)
	if err != nil || len(pt) != 65 || pt[0] != 0x04 {
		t.Fatalf("bad EC point hex: %v", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pt[1:33]),
		Y:     new(big.Int).SetBytes(pt[33:65]),
	}
}

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "se-pkcs11-signer-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func makeLeaf(t *testing.T, pub *ecdsa.PublicKey, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return der
}

func writePEM(t *testing.T, path string, der []byte) {
	t.Helper()
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, p, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}
