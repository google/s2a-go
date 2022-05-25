// Static implementation of TLS Configuration Store (no calls to S2Av2)
package tls_config_store

import (
	"log"
	"crypto/tls"
	"crypto/x509"

	_ "embed"

	rs "//internal/v2/remote_signer"
	cv "//internal/v2/certificate_verifier"
)

// Static implementation. In future, ask S2Av2 for these values.
var (
	//go:embed //internal/v2/example_cert_key/client_cert.pem
	clientCert []byte
	//go:embed //internal/v2/example_cert_key/server_cert.pem
	serverCert []byte
)

GetTlsConfigurationForClient(id string) tls.Config {
	// Static implementation. In future, ask S2Av2 for these values.
	min_version := tls.VersionTLS13
	max_version := tls.VersionTLS13
	cipher_suites := nil
	curve_prefernces := nil
	cert := tls.Certificate {
		Certificate = clientCert,
		PrivateKey = // TODO : call remote signer library
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(serverCert)

	// Create mTLS credentials for client.
	config := tls.Config {
		Certificates = []tls.Certificate{cert},
		VerifyPeerCertificate = , // TODO : call cert verifier library
		RootCAs = rootCertPool,
		InsecureSkipVerify = true,
		CipherSuites = cipher_suites,
		ClientSessionCache = nil,
		MinVersion = min_version,
		MaxVersion = max_version,
		CurvePreferences = curve_preferences,
	}
	return config
}

GetTlsConfigurationForServer(id string, server_name string) tls.Config {
	// Static implementation. In future, ask S2Av2 for these values.
	min_version := tls.VersionTLS13
	max_version := tls.VersionTLS13
	cipher_suites := nil
	curve_prefernces := nil
	client_auth := tls.RequireAndVerifyClientCert
	cert := tls.Certificate {
		Certificate = serverCert,
		PrivateKey = // TODO : call remote signer library
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(clientCert)

	// Create mTLS credentials for client.
	config := tls.Config {
		Certificates = []tls.Certificate{cert},
		VerifyPeerCertificate = , // TODO : call cert verifier library
		ClientAuth = client_auth,
		ClientCAs = certPool
		InsecureSkipVerify = true,
		CipherSuites = cipher_suites,
		MinVersion = min_version,
		MaxVersion = max_version,
		CurvePreferences = curve_preferences,
	}
	return config
}
