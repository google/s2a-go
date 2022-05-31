package certverifier

import (
	"testing"
	"crypto/x509"
	"crypto/tls"

	_ "embed"
)

var (
	//go:embed example_cert_key/client_cert.pem
	clientCert []byte
	//go:embed example_cert_key/server_cert.pem
	serverCert []byte
	//go:embed example_cert_key/client_key.pem
	clientKey []byte
	//go:embed example_cert_key/server_key.pem
	serverKey []byte
)

// TestVerifyClientCertChain runs unit tests for VerifyClientCertificateChain.
func TestVerifyClientCertChain(t *testing.T) {
	// Setup for static client test : empty certPool.
	certPool0 := x509.NewCertPool()

	// Setup for static client test : non-empty certPool.
	certPool1 := x509.NewCertPool()
	certPool1.AppendCertsFromPEM(serverCert)
	cert1, err1 := tls.X509KeyPair(serverCert, serverKey)
	if err1 != nil {
		t.Errorf("Test suite setup failed: %v", err1)
	}

	for _, tc := range []struct {
		description              string
		pool                     *x509.CertPool
		expectedCommonName       string
		rawCerts                 [][]byte
		verifiedChains           [][]*x509.Certificate
		err                      error
	}{
		{
			description: "static : empty certPool",
			pool: certPool0,
			expectedCommonName: "s2a_test_cert",
			rawCerts: nil,
			verifiedChains: nil,
			err: nil,
		},
		{
			description: "static : non-empty certPool",
			pool: certPool1,
			expectedCommonName: "s2a_test_cert",
			rawCerts: cert1.Certificate,
			verifiedChains: [][]*x509.Certificate{{cert1.Leaf},{}},
			err: nil,
		},
	}{
		t.Run(tc.description, func(t *testing.T) {
			VerifyPeerCertificateFunc := VerifyClientCertificateChain(tc.expectedCommonName, tc.pool)
			if got, want := VerifyPeerCertificateFunc(tc.rawCerts, tc.verifiedChains), tc.err; got != want {
				t.Errorf("Peer Certificate verification failed: %v", got)
			}
		})
	}
}

// TestVerifyServerCertChain runs unit tests for VerifyServerCertificateChain.
func TestVerifyServerCertChain(t *testing.T) {
	// Setup for static server test : empty certPool.
	certPool0 := x509.NewCertPool()

	// Setup for static server test : non-empty certPool.
	certPool1 := x509.NewCertPool()
	certPool1.AppendCertsFromPEM(clientCert)
	cert1, err1 := tls.X509KeyPair(clientCert, clientKey)
	if err1 != nil {
		t.Errorf("Test suite setup failed: %v", err1)
	}

	for _, tc := range []struct {
		description              string
		pool                     *x509.CertPool
		expectedCommonName       string
		hostname                 string
		rawCerts                 [][]byte
		verifiedChains           [][]*x509.Certificate
		err                      error
	}{
		{
			description: "static : empty certPool",
			pool: certPool0,
			expectedCommonName: "s2a_test_cert",
			hostname: "host",
			rawCerts: nil,
			verifiedChains: nil,
			err: nil,
		},
		{
			description: "static : non-empty certPool",
			pool: certPool1,
			expectedCommonName: "s2a_test_cert",
			hostname: "host",
			rawCerts: cert1.Certificate,
			verifiedChains: [][]*x509.Certificate{{cert1.Leaf},{}},
			err: nil,
		},
	}{
		t.Run(tc.description, func(t *testing.T) {
			VerifyPeerCertificateFunc := VerifyServerCertificateChain(tc.expectedCommonName, tc.hostname, tc.pool)
			if got, want := VerifyPeerCertificateFunc(tc.rawCerts, tc.verifiedChains), tc.err; got != want {
				t.Errorf("Peer Certificate verification failed: %v", got)
			}
		})
	}
}
