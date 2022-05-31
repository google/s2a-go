package remotesigner

import (
	"testing"
	"crypto"
	"crypto/tls"
	_ "embed"
)

var (
	//go:embed example_cert_key/cert.pem
	cert []byte
	//go:embed example_cert_key/key.pem
	key []byte
)

// TestNewSigner runs unit test for New.
func TestNewSigner(t *testing.T) {
	// Setup for static test.
	cert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Errorf("failed to parse PEM cert and key: %v", err)
	}

	if got, want := New(&cert), cert.PrivateKey.(crypto.Signer); got != want {
		t.Errorf("RemoteSigner instance is incorrect. got: %v, want: %v", got, want)
	}
}
