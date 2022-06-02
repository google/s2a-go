// Builds TLS configurations that offload operations to S2Av2.
package tlsconfigstore

import (
	"log"
	"crypto/tls"
	"crypto/x509"
	"github.com/google/s2a-go/internal/v2/cert_verifier"

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

// GetTlsConfigurationForClient returns a tls.Config instance for use by a client application.
func GetTlsConfigurationForClient(serverHostname string) *tls.Config {
	// TODO(rmehta19): Call S2Av2 for certificate.
	// TODO(rmehta19): Call remote signer library for private key.
	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		log.Fatalf("Failed to generate X509KeyPair: %v", err)
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(serverCert)

	// TODO(rmehta19): Call S2Av2 for config values.
	// Create mTLS credentials for client.
	return &tls.Config {
		Certificates: []tls.Certificate{cert},
		VerifyPeerCertificate: certverifier.VerifyServerCertificateChain("s2a_test_cert", serverHostname, rootCertPool),
		RootCAs: rootCertPool,
		ServerName: serverHostname,
		InsecureSkipVerify: true,
		ClientSessionCache: nil,
		MinVersion: uint16(tls.VersionTLS13),
		MaxVersion: uint16(tls.VersionTLS13),
	}
}

// GetTlsConfigurationForServer returns a tls.Config instance for use by a server application.
func GetTlsConfigurationForServer() *tls.Config {
	// TODO(rmehta19): Call S2Av2 for certificate.
	// TODO(rmehta19): Call remote signer library for private key.
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatalf("Failed to generate X509KeyPair: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(clientCert)


	// TODO(rmehta19): Call S2Av2 for config values.
	// Create mTLS credentials for server.
	return &tls.Config {
		Certificates: []tls.Certificate{cert},
		VerifyPeerCertificate: certverifier.VerifyClientCertificateChain("s2a_test_cert", certPool),
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: certPool,
		InsecureSkipVerify: true,
		MinVersion: uint16(tls.VersionTLS13),
		MaxVersion: uint16(tls.VersionTLS13),
	}
}
