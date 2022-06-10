// Builds TLS configurations that offload operations to S2Av2.
package tlsconfigstore

import (
	"log"
	"crypto/tls"
	"crypto/x509"
	"github.com/google/s2a-go/internal/v2/cert_verifier"

	_ "embed"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
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
func GetTlsConfigurationForClient(serverHostname string, cstream s2av2pb.S2AService_SetUpSessionClient) *tls.Config {
	// Send request to S2Av2 for config.
	err := cstream.Send(&s2av2pb.SessionReq {
		AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
			{
				// TODO(rmehta19): Populate Authentication Mechanism using tokenmanager.
				MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
			},
		},
		ReqOneof: &s2av2pb.SessionReq_GetTlsConfigurationReq {
			&s2av2pb.GetTlsConfigurationReq {
				ConnectionSide: commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT,
			},
		},
	})
	if err != nil {
		log.Fatalf("Client: failed to send SessionReq: %v", err)
	}
	log.Printf("Client: sent SessionReq")

	// Get the response containing config from S2Av2.
	resp, err := cstream.Recv()
	if err != nil {
		log.Fatalf("Client: failed to recieve SessionResp: %v", err)
	}
	log.Printf("Client: recieved SessionResp")

	// TODO(rmehta19): Handle resp.GetStatus().

	// Extract TLS configiguration from SessionResp.
	tlsConfig := resp.GetGetTlsConfigurationResp().GetClientTlsConfiguration()

	// Fake S2Av2 only puts one cert in CertitificateChain, for loop iterates
	// once.
	var certList []tls.Certificate
	for _, v := range tlsConfig.CertificateChain {
		// TODO(rmehta19): Call remote signer library for private key.
		cert, err := tls.X509KeyPair([]byte(v), clientKey)
		if err != nil {
			log.Fatalf("Failed to generate X509KeyPair: %v", err)
		}
		certList = append(certList, cert)
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(serverCert)

	// Map S2Av2 TLSVersion to consts defined in tls package.
	var minVersion uint16
	var maxVersion uint16
	switch x := tlsConfig.MinTlsVersion; x {
	case commonpb.TLSVersion_TLS_VERSION_1_0:
		minVersion = tls.VersionTLS10
	case commonpb.TLSVersion_TLS_VERSION_1_1:
		minVersion = tls.VersionTLS11
	case commonpb.TLSVersion_TLS_VERSION_1_2:
		minVersion = tls.VersionTLS12
	case commonpb.TLSVersion_TLS_VERSION_1_3:
		minVersion = tls.VersionTLS13
	default:
		minVersion = tls.VersionTLS13
	}

	switch x := tlsConfig.MaxTlsVersion; x {
	case commonpb.TLSVersion_TLS_VERSION_1_0:
		maxVersion = tls.VersionTLS10
	case commonpb.TLSVersion_TLS_VERSION_1_1:
		maxVersion = tls.VersionTLS11
	case commonpb.TLSVersion_TLS_VERSION_1_2:
		maxVersion = tls.VersionTLS12
	case commonpb.TLSVersion_TLS_VERSION_1_3:
		maxVersion = tls.VersionTLS13
	default:
		maxVersion = tls.VersionTLS13
	}

	// Create mTLS credentials for client.
	return &tls.Config {
		// TODO(rmehta19): Make use of tlsConfig.HandshakeCiphersuites /
		// RecordCiphersuites.
		Certificates: certList,
		VerifyPeerCertificate: certverifier.VerifyServerCertificateChain("s2a_test_cert", serverHostname, rootCertPool),
		RootCAs: rootCertPool,
		ServerName: serverHostname,
		InsecureSkipVerify: true,
		ClientSessionCache: nil,
		MinVersion: minVersion,
		MaxVersion: maxVersion,
	}
}

// GetTlsConfigurationForServer returns a tls.Config instance for use by a server application.
func GetTlsConfigurationForServer(cstream s2av2pb.S2AService_SetUpSessionClient) *tls.Config {
	// Send request to S2Av2 for config.
	err := cstream.Send(&s2av2pb.SessionReq {
		AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
			{
				// TODO(rmehta19): Populate Authentication Mechanism using tokenmanager.
				MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
			},
		},
		ReqOneof: &s2av2pb.SessionReq_GetTlsConfigurationReq {
			&s2av2pb.GetTlsConfigurationReq {
				ConnectionSide: commonpb.ConnectionSide_CONNECTION_SIDE_SERVER,
			},
		},
	})
	if err != nil {
		log.Fatalf("Client: failed to send SessionReq: %v", err)
	}
	log.Printf("Client: sent SessionReq")

	// Get the response containing config from S2Av2.
	resp, err := cstream.Recv()
	if err != nil {
		log.Fatalf("Client: failed to recieve SessionResp: %v", err)
	}
	log.Printf("Client: recieved SessionResp")

	// TODO(rmehta19): Handle resp.GetStatus().

	// Extract TLS configiguration from SessionResp.
	tlsConfig := resp.GetGetTlsConfigurationResp().GetServerTlsConfiguration()
	var certList []tls.Certificate
	// Fake S2Av2 only puts one cert in CertitificateChain, for loop iterates
	// once.
	for _, v := range tlsConfig.CertificateChain {
		// TODO(rmehta19): Call remote signer library for private key.
		cert, err := tls.X509KeyPair([]byte(v), serverKey)
		if err != nil {
			log.Fatalf("Failed to generate X509KeyPair: %v", err)
		}
		certList = append(certList, cert)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(clientCert)

	// Map S2Av2 TLSVersion to consts defined in tls package.
	var minVersion uint16
	var maxVersion uint16
	switch x := tlsConfig.MinTlsVersion; x {
	case commonpb.TLSVersion_TLS_VERSION_1_0:
		minVersion = tls.VersionTLS10
	case commonpb.TLSVersion_TLS_VERSION_1_1:
		minVersion = tls.VersionTLS11
	case commonpb.TLSVersion_TLS_VERSION_1_2:
		minVersion = tls.VersionTLS12
	case commonpb.TLSVersion_TLS_VERSION_1_3:
		minVersion = tls.VersionTLS13
	default:
		minVersion = tls.VersionTLS13
	}

	switch x := tlsConfig.MaxTlsVersion; x {
	case commonpb.TLSVersion_TLS_VERSION_1_0:
		maxVersion = tls.VersionTLS10
	case commonpb.TLSVersion_TLS_VERSION_1_1:
		maxVersion = tls.VersionTLS11
	case commonpb.TLSVersion_TLS_VERSION_1_2:
		maxVersion = tls.VersionTLS12
	case commonpb.TLSVersion_TLS_VERSION_1_3:
		maxVersion = tls.VersionTLS13
	default:
		maxVersion = tls.VersionTLS13
	}

	if minVersion > maxVersion {
		log.Printf("S2Av2 provided minVersion > maxVersion")
	}

	// Create mTLS credentials for server.
	return &tls.Config {
		// TODO(rmehta19): Make use of tlsConfig.HandshakeCiphersuites /
		// RecordCiphersuites / TlsResumptionEnabled / MaxOverheadOfTicketAead.
		Certificates: certList,
		VerifyPeerCertificate: certverifier.VerifyClientCertificateChain("s2a_test_cert", certPool),
		// TODO(rmehta19): Remove "+ 2" when proto file enum change is merged.
		ClientAuth: tls.ClientAuthType(tlsConfig.RequestClientCertificate) + 2,
		ClientCAs: certPool,
		InsecureSkipVerify: true,
		MinVersion: minVersion,
		MaxVersion: maxVersion,
	}
}
