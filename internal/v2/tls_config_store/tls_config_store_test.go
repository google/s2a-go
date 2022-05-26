package tls_config_store

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


// TODO(riyamehta) : In Client and Server test, verify contents of config.RootCAs once x509.CertPool.Equal function is officially released : https://cs.opensource.google/go/go/+/4aacb7ff0f103d95a724a91736823f44aa599634 .

func TestTLSConfigStoreClient(t *testing.T) {
	// Setup for static client test.
	cert, err := tls.X509KeyPair(clientCertpem, clientKeypem)
	if err != nil {
		t.Errorf("Test suite setup failed")
	}
	// certPool := x509.NewCertPool()
        // certPool.AppendCertsFromPEM(serverCertpem)

	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		// RootCAs 		    *x509.CertPool
		InsecureSkipVerify          bool
		CipherSuites	            []uint16
		ClientSessionCache	    tls.ClientSessionCache
		MinVersion	            uint16
		MaxVersion		    uint16
		CurvePreferences	    []tls.CurveID
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			// RootCAs: certPool,
			InsecureSkipVerify: true,
			CipherSuites: nil,
			ClientSessionCache: nil,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			CurvePreferences: nil,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			config := GetTlsConfigurationForClient("abc")
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got, want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			/*if got, want := config.RootCAs, tc.RootCAs; !got.Equal(want){
				t.Errorf("config.RootCAs = %v, want %v", got, want)
			}*/
			if got, want := config.InsecureSkipVerify, tc.InsecureSkipVerify; got != want {
				t.Errorf("config.InsecureSkipVerify = %v, want %v", got, want)
			}
			if got, want := len(config.CipherSuites), len(tc.CipherSuites); (got != want) {
				t.Errorf("len(config.CipherSuites) = %v, want %v", got, want)
			}
			for i, v := range config.CipherSuites { if v != tc.CipherSuites[i] { t.Errorf("config.CipherSuites = %v, want %v", config.CipherSuites, tc.CipherSuites) } }
			if got, want := config.ClientSessionCache, tc.ClientSessionCache; got != want {
				t.Errorf("config.ClientSessionCache = %v, want %v", got, want)
			}
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
			if got, want := len(config.CurvePreferences), len(tc.CurvePreferences); got != want {
				t.Errorf("len(config.CurvePreferences) = %v, want %v", got, want)
			}
			for i, v := range config.CurvePreferences { if v != tc.CurvePreferences[i] { t.Errorf("config.CurvePreferences = %v, want %v", config.CurvePreferences, tc.CurvePreferences) } }
		})
	}
}

func TestTLSConfigStoreServer(t *testing.T) {
	// Setup for static server test.
	cert, err := tls.X509KeyPair(serverCertpem, serverKeypem)
	if err != nil {
		t.Errorf("Test suite setup failed")
	}
	// certPool := x509.NewCertPool()
        // certPool.AppendCertsFromPEM(clientCertpem)

	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		ClientAuth		    tls.ClientAuthType
		// ClientCAs		    *x509.CertPool
		InsecureSkipVerify          bool
		CipherSuites	            []uint16
		MinVersion	            uint16
		MaxVersion		    uint16
		CurvePreferences	    []tls.CurveID
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAndVerifyClientCert,
			// ClientCAs: certPool,
			InsecureSkipVerify: true,
			CipherSuites: nil,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			CurvePreferences: nil,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			config := GetTlsConfigurationForServer("abc", "s2a_test_cert")
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got,want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			if got, want := config.ClientAuth, tc.ClientAuth; got != want {
				t.Errorf("config.ClientAuth = %v, want %v", got, want)
			}
			/*if got, want := config.ClientCAs, tc.ClientCAs; !got.Equal(want) {
				t.Errorf("config.ClientCAs = %v, want %v", got, want)
			}*/
			if got, want := config.InsecureSkipVerify, tc.InsecureSkipVerify; got != want {
				t.Errorf("config.InsecureSkipVerify = %v, want %v", got, want)
			}
			if got, want := len(config.CipherSuites), len(tc.CipherSuites); (got != want) {
				t.Errorf("len(config.CipherSuites) = %v, want %v", got, want)
			}
			for i, v := range config.CipherSuites { if v != tc.CipherSuites[i] { t.Errorf("config.CipherSuites = %v, want %v", config.CipherSuites, tc.CipherSuites) } }
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
			if got, want := len(config.CurvePreferences), len(tc.CurvePreferences); got != want {
				t.Errorf("len(config.CurvePreferences) = %v, want %v", got, want)
			}
			for i, v := range config.CurvePreferences { if v != tc.CurvePreferences[i] { t.Errorf("config.CurvePreferences = %v, want %v", config.CurvePreferences, tc.CurvePreferences) } }
		})
	}
}
