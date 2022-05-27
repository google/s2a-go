// Static implementation of TLS Configuration Store (no calls to S2Av2, Remote Signer Library, Certificate Verifier)
package tls_config_store

import (
	"log"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	_ "embed"
)

var (
	//go:embed s2a-go/internal/v2/example_cert_key/client_cert.pem
	clientCert []byte
	//go:embed s2a-go/internal/v2/example_cert_key/server_cert.pem
	serverCert []byte
	//go:embed s2a-go/internal/v2/example_cert_key/client_key.pem
	clientKey []byte
	//go:embed s2a-go/internal/v2/example_cert_key/server_key.pem
	serverKey []byte
)

func VerifyPeerCertificateFunc(instanceName string, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate to verify")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("x509.ParseCertificate(rawCerts[0]) returned error: %v", err)
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


func GetTlsConfigurationForClient(id string) tls.Config {
	// Static implementation. TODO : Call S2Av2 for these values.
	min_version := uint16(tls.VersionTLS13)
	max_version := uint16(tls.VersionTLS13)
	var cipher_suites []uint16
	var curve_preferences []tls.CurveID

	// Static implementation. TODO : Call remote signer library for Private Key.
	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		log.Fatalf("Failed to get client cert")
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(serverCert)

	// Create mTLS credentials for client.
	config := tls.Config {
		Certificates: []tls.Certificate{cert},
		VerifyPeerCertificate: VerifyPeerCertificateFunc("s2a_test_cert", rootCertPool), // Static implementation. TODO : Call cert verifier library.
		RootCAs: rootCertPool,
		InsecureSkipVerify: true,
		CipherSuites: cipher_suites,
		ClientSessionCache: nil,
		MinVersion: min_version,
		MaxVersion: max_version,
		CurvePreferences: curve_preferences,
	}
	return config
}


func GetTlsConfigurationForServer(id string, server_name string) tls.Config {
	// Static implementation. TODO : Call S2Av2 for these values.
	min_version := uint16(tls.VersionTLS13)
	max_version := uint16(tls.VersionTLS13)
	var cipher_suites []uint16
	var curve_preferences []tls.CurveID
	client_auth := tls.RequireAndVerifyClientCert

	// Static implementation. TODO : Call remote signer library for Private Key.
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatalf("Failed to get server cert")
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(clientCert)

	// Create mTLS credentials for server.
	config := tls.Config {
		Certificates: []tls.Certificate{cert},
		VerifyPeerCertificate: VerifyPeerCertificateFunc("s2a_test_cert", certPool), // Static implementation. TODO : Call cert verifier library.
		ClientAuth: client_auth,
		ClientCAs: certPool,
		InsecureSkipVerify: true,
		CipherSuites: cipher_suites,
		MinVersion: min_version,
		MaxVersion: max_version,
		CurvePreferences: curve_preferences,
	}
	return config
}
