// Builds TLS configurations that offload operations to S2Av2.
package tlsconfigstore

import (
	"log"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

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
func GetTlsConfigurationForClient() *tls.Config {
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
		VerifyPeerCertificate: verifyPeerCertificateFunc("s2a_test_cert", rootCertPool), // TODO(rmehta19): Call cert verifier library.
		RootCAs: rootCertPool,
		InsecureSkipVerify: true,
		ClientSessionCache: nil,
		MinVersion: uint16(tls.VersionTLS13),
		MaxVersion: uint16(tls.VersionTLS13),
	}
}

// GetTlsConfigurationForServer returns a tls.Config instance for use by a server application.
func GetTlsConfigurationForServer() *tls.Config {
	// TODO(rmehta19): Call remote signer library for Private Key.
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
		VerifyPeerCertificate: verifyPeerCertificateFunc("s2a_test_cert", certPool), // TODO(rmehta19): Call cert verifier library.
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: certPool,
		InsecureSkipVerify: true,
		MinVersion: uint16(tls.VersionTLS13),
		MaxVersion: uint16(tls.VersionTLS13),
	}
}

// TODO(rmehta19): Remove this static implementation once Certificate Verifier library(contains APIs for VerifyClientCertificateChain and VerifyServerCertificateChain) implementation completed.
func verifyPeerCertificateFunc(instanceName string, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate to verify")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("ParseCertificate failed: %v", err)
		}

		opts := x509.VerifyOptions{
			CurrentTime: time.Now(),
			Roots:       pool,
		}

		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		if cert.Subject.CommonName != instanceName {
			return fmt.Errorf("certificate had Common Name %q, expected %q", cert.Subject.CommonName, instanceName)
		}
		return nil
	}
}
