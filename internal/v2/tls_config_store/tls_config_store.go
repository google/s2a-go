// Builds TLS configurations that offload operations to S2Av2.
package tlsconfigstore

import (
	"errors"
	"crypto/tls"
	"encoding/pem"
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
func GetTlsConfigurationForClient(serverHostname string, cstream s2av2pb.S2AService_SetUpSessionClient) (*tls.Config, error) {
	// Send request to S2Av2 for config.
	if err := cstream.Send(&s2av2pb.SessionReq {
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
	}); err != nil {
		return nil, err
	}

	// Get the response containing config from S2Av2.
	resp, err := cstream.Recv()
	if err != nil {
		return nil, err
	}

	// TODO(rmehta19): Handle resp.GetStatus().

	// Extract TLS configiguration from SessionResp.
	tlsConfig := resp.GetGetTlsConfigurationResp().GetClientTlsConfiguration()

	var cert tls.Certificate
	for _, v := range tlsConfig.CertificateChain {
		// Populate Certificates field
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return nil, errors.New("certificate in CertificateChain obtained from S2Av2 is empty.")
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		cert.Certificate = append(cert.Certificate, x509Cert.Raw)
	}

	// Until TODO resolved, populate PrivateKey field using leaf cert and
	// corresponding key.
	// TODO(rmehta19): Call remote signer library for private key.
	tlsCert, _ := tls.X509KeyPair([]byte(tlsConfig.CertificateChain[0]), clientKey)
	cert.PrivateKey = tlsCert.PrivateKey

	// TODO(rmehta19): Remove certPool when RPC containing
	// ValidatePeerCertificateChainReq implemented.
	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(serverCert)

	minVersion, maxVersion := getTLSMinMaxVersionsClient(tlsConfig)
	if minVersion > maxVersion {
		return nil, errors.New("S2Av2 provided minVersion > maxVersion.")
	}

	// Create mTLS credentials for client.
	return &tls.Config {
		// TODO(rmehta19): Make use of tlsConfig.HandshakeCiphersuites /
		// RecordCiphersuites.
		Certificates: []tls.Certificate{cert},
		VerifyPeerCertificate: certverifier.VerifyServerCertificateChain("s2a_test_cert", serverHostname, rootCertPool),
		RootCAs: rootCertPool,
		ServerName: serverHostname,
		InsecureSkipVerify: true,
		ClientSessionCache: nil,
		MinVersion: minVersion,
		MaxVersion: maxVersion,
	}, nil
}

// GetTlsConfigurationForServer returns a tls.Config instance for use by a server application.
func GetTlsConfigurationForServer(cstream s2av2pb.S2AService_SetUpSessionClient) (*tls.Config, error) {
	// TODO(rmehta19): move call to S2Av2 to a helper function.
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
		return nil, err
	}

	// Get the response containing config from S2Av2.
	resp, err := cstream.Recv()
	if err != nil {
		return nil, err
	}

	// TODO(rmehta19): Handle resp.GetStatus().

	// Extract TLS configiguration from SessionResp.
	tlsConfig := resp.GetGetTlsConfigurationResp().GetServerTlsConfiguration()

	var cert tls.Certificate
	for _, v := range tlsConfig.CertificateChain {
		// Populate Certificates field
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return nil, errors.New("certificate in CertificateChain obtained from S2Av2 is empty.")
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		cert.Certificate = append(cert.Certificate, x509Cert.Raw)
	}

	// Until TODO resolved, populate PrivateKey field using leaf cert and
	// corresponding key.
	// TODO(rmehta19): Call remote signer library for private key.
	tlsCert, _ := tls.X509KeyPair([]byte(tlsConfig.CertificateChain[0]), serverKey)
	cert.PrivateKey = tlsCert.PrivateKey

	// TODO(rmehta19): Remove certPool when RPC containing
	// ValidatePeerCertificateChainReq implemented.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(clientCert)

	minVersion, maxVersion := getTLSMinMaxVersionsServer(tlsConfig)
	if minVersion > maxVersion {
		return nil, errors.New("S2Av2 provided minVersion > maxVersion")
	}

	// Create mTLS credentials for server.
	return &tls.Config {
		// TODO(rmehta19): Make use of tlsConfig.HandshakeCiphersuites /
		// RecordCiphersuites / TlsResumptionEnabled / MaxOverheadOfTicketAead.
		Certificates: []tls.Certificate{cert},
		VerifyPeerCertificate: certverifier.VerifyClientCertificateChain("s2a_test_cert", certPool),
		ClientCAs: certPool,
		// TODO(rmehta19): Remove "+ 2" when proto file enum change is merged.
		ClientAuth: tls.ClientAuthType(tlsConfig.RequestClientCertificate) + 2,
		InsecureSkipVerify: true,
		MinVersion: minVersion,
		MaxVersion: maxVersion,
	}, nil
}

func getTLSMinMaxVersionsClient(tlsConfig *s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration) (uint16, uint16){
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
	return minVersion, maxVersion
}

func getTLSMinMaxVersionsServer(tlsConfig *s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration) (uint16, uint16){
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
	return minVersion, maxVersion
}
