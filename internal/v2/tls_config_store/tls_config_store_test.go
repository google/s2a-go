package tlsconfigstore

import (
	"testing"
	"crypto/tls"
	"bytes"

	_ "embed"
)

var (
	//go:embed example_cert_key/client_cert.pem
	clientCertpem []byte
	//go:embed example_cert_key/server_cert.pem
	serverCertpem []byte
	//go:embed example_cert_key/client_key.pem
	clientKeypem []byte
	//go:embed example_cert_key/server_key.pem
	serverKeypem []byte
)


// TODO(rmehta19): In Client and Server test, verify contents of config.RootCAs once x509.CertPool.Equal function is officially released : https://cs.opensource.google/go/go/+/4aacb7ff0f103d95a724a91736823f44aa599634 .

// TestTLSConfigStoreClient runs unit tests for GetTlsConfigurationForClient.
func TestTLSConfigStoreClient(t *testing.T) {
	// Setup for static client test.
	cert, err := tls.X509KeyPair(clientCertpem, clientKeypem)
	if err != nil {
		t.Errorf("Test suite setup failed")
	}

	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		ServerName	            string
		InsecureSkipVerify          bool
		ClientSessionCache	    tls.ClientSessionCache
		MinVersion	            uint16
		MaxVersion		    uint16
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			ServerName: "host",
			InsecureSkipVerify: true,
			ClientSessionCache: nil,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			config := GetTlsConfigurationForClient(tc.ServerName)
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got, want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			if got, want := config.InsecureSkipVerify, tc.InsecureSkipVerify; got != want {
				t.Errorf("config.InsecureSkipVerify = %v, want %v", got, want)
			}
			if got, want := config.ClientSessionCache, tc.ClientSessionCache; got != want {
				t.Errorf("config.ClientSessionCache = %v, want %v", got, want)
			}
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
		})
	}
}

// TestTLSConfigStoreServer runs unit tests for GetTLSConfigurationForServer.
func TestTLSConfigStoreServer(t *testing.T) {
	// Setup for static server test.
	cert, err := tls.X509KeyPair(serverCertpem, serverKeypem)
	if err != nil {
		t.Errorf("Test suite setup failed")
	}

	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		ClientAuth		    tls.ClientAuthType
		InsecureSkipVerify          bool
		MinVersion	            uint16
		MaxVersion		    uint16
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAndVerifyClientCert,
			InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			config := GetTlsConfigurationForServer()
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got,want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			if got, want := config.ClientAuth, tc.ClientAuth; got != want {
				t.Errorf("config.ClientAuth = %v, want %v", got, want)
			}
			if got, want := config.InsecureSkipVerify, tc.InsecureSkipVerify; got != want {
				t.Errorf("config.InsecureSkipVerify = %v, want %v", got, want)
			}
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
		})
	}
}
