// Builds TLS configurations that offload operations to S2Av2.
package tlsconfigstore

import (
	"crypto/tls"
	"crypto/x509"
	"context"
	"flag"
	"log"
	"time"
	"github.com/google/s2a-go/internal/v2/cert_verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	_ "embed"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
)

const (
	defaultTimeout = 10.0 * time.Second
)

var (
	fakes2av2Addr = flag.String("fakes2av2_Addr", "0.0.0.0:8080", "Fake S2Av2 service address.")
	//go:embed example_cert_key/client_key.pem
	clientKey []byte
	//go:embed example_cert_key/server_key.pem
	serverKey []byte
)

// GetTlsConfigurationForClient returns a tls.Config instance for use by a client application.
func GetTlsConfigurationForClient(serverHostname string) *tls.Config {
	// TODO(rmehta19): Reuse this connection per session across all libraries. Perhaps move the connection setup to s2av2.go.
	// Setup connection to fake S2Av2.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithReturnConnectionError(),
		grpc.WithBlock(),
	}
	conn, err := grpc.Dial(*fakes2av2Addr, opts...)
	if err != nil {
		log.Fatalf("Client Application: failed to connect: %v", err)
	}
	defer conn.Close()
	c := s2av2pb.NewS2AServiceClient(conn)
	log.Printf("Client Application: connected to: %s", *fakes2av2Addr)
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	// Call fake S2Av2 for cofig.
	r, err := c.GetTlsConfiguration(ctx, &s2av2pb.GetTlsConfigurationReq{
		ConnectionSide: commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT,
		Sni: "",
	})
	if err != nil {
		log.Fatalf("Client Application: failed to send GetTlsConfigurationReq: %v", err)
	}
	log.Printf("Client Application: recieved GetTlsConfigurationResponse from server")

	// TODO(rmehta19): Call remote signer library for private key.
	cert, err := tls.X509KeyPair(r.certificate_chain[0], clientKey)
	if err != nil {
		log.Fatalf("Failed to generate X509KeyPair: %v", err)
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(serverCert)

	// Create mTLS credentials for client.
	return &tls.Config {
		Certificates: []tls.Certificate{cert},
		VerifyPeerCertificate: certverifier.VerifyServerCertificateChain("s2a_test_cert", serverHostname, rootCertPool),
		RootCAs: rootCertPool,
		ServerName: serverHostname,
		InsecureSkipVerify: true,
		ClientSessionCache: nil,
		MinVersion: r.min_tls_version,
		MaxVersion: r.max_tls_version,
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
