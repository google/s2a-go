package certverifier

import (
	"sync"
	"log"
	"time"
	"errors"
	"context"
	"net"
	"testing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/google/s2a-go/internal/v2/fakes2av2"

	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	_ "embed"
)

const (
	defaultTimeout = 10.0 * time.Second
)

var (
	//go:embed example_cert_key/client_root_cert.der
	clientRootDERCert []byte
	//go:embed example_cert_key/client_intermediate_cert.der
	clientIntermediateDERCert []byte
	//go:embed example_cert_key/client_leaf_cert.der
	clientLeafDERCert []byte
	//go:embed example_cert_key/server_root_cert.der
	serverRootDERCert []byte
	//go:embed example_cert_key/server_intermediate_cert.der
	serverIntermediateDERCert []byte
	//go:embed example_cert_key/server_leaf_cert.der
	serverLeafDERCert []byte
)


func startFakeS2Av2Server(wg *sync.WaitGroup) (stop func(), address string, err error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("failed to listen on address %s: %v", address, err)
	}
	address = listener.Addr().String()
	s := grpc.NewServer()
	log.Printf("Server: started gRPC fake S2Av2 Server on address: %s", address)
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{})
	go func() {
		wg.Done()
		if err := s.Serve(listener); err != nil {
			log.Printf("failed to serve: %v", err)
		}
	}()
	return func() { s.Stop()}, address, nil
}

// TestVerifyClientCertChain runs unit tests for VerifyClientCertificateChain.
func TestVerifyClientCertChain(t *testing.T) {
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		log.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	for _, tc := range []struct {
		description              string
		rawCerts                 [][]byte
		expectedErr	         error
	}{
		{
			description: "empty chain",
			rawCerts: nil,
			expectedErr: errors.New("Failed to offload client cert verification to S2A: 3, Client Peer Verification failed: client cert chain is empty."),
		},
		{
			description: "chain of length 1",
			rawCerts: [][]byte{clientRootDERCert,},
			expectedErr: nil,
		},
		{
			description: "chain of length 2 correct",
			rawCerts: [][]byte{clientLeafDERCert, clientIntermediateDERCert, },
			expectedErr: nil,
		},
		{
			description: "chain of length 2 error: missing intermediate",
			rawCerts: [][]byte{clientLeafDERCert, clientRootDERCert,},
			expectedErr: errors.New("Failed to offload client cert verification to S2A: 3, Client Peer Verification failed: x509: certificate signed by unknown authority (possibly because of \"crypto/rsa: verification error\" while trying to verify candidate authority certificate \"s2a_test_cert\")"),
		},
	}{
		t.Run(tc.description, func(t *testing.T) {
			// Create new stream to S2Av2.
			opts := []grpc.DialOption {
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithReturnConnectionError(),
				grpc.WithBlock(),
			}
			conn, err := grpc.Dial(address, opts...)
			if err != nil {
				log.Fatalf("Client: failed to connect: %v", err)
			}
			defer conn.Close()
			c := s2av2pb.NewS2AServiceClient(conn)
			log.Printf("Client: connected to: %s", address)
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Setup bidrectional streaming session.
			callOpts := []grpc.CallOption{}
			cstream, err := c.SetUpSession(ctx, callOpts...)
			if err != nil  {
				log.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
			}
			log.Printf("Client: set up bidirectional streaming RPC session.")

			VerifyPeerCertificateFunc := VerifyClientCertificateChain(cstream)
			got, want := VerifyPeerCertificateFunc(tc.rawCerts, nil), tc.expectedErr
			if want == nil {
				if got != nil {
					t.Errorf("Peer Certificate verification failed, got: %v, want: %v", got, want)
				}
			} else {
				if got == nil {
					t.Errorf("Peer Certificate verification failed, got: %v, want: %v", got, want)
				}
				if got.Error() != want.Error() {
					t.Errorf("Peer Certificate verification failed, got: %v, want: %v", got, want)
				}
			}
		})
	}
	stop()
}

// TestVerifyServerCertChain runs unit tests for VerifyServerCertificateChain.
func TestVerifyServerCertChain(t *testing.T) {
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		log.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	for _, tc := range []struct {
		description              string
		hostname                 string
		rawCerts                 [][]byte
		expectedErr              error
	}{
		{
			description: "empty chain",
			hostname: "host",
			rawCerts: nil,
			expectedErr: errors.New("Failed to offload client cert verification to S2A: 3, Server Peer Verification failed: server cert chain is empty."),
		},
		{
			description: "chain of length 1",
			hostname: "host",
			rawCerts: [][]byte{serverRootDERCert, },
			expectedErr: nil,
		},
		{
			description: "chain of length 2 correct",
			hostname: "host",
			rawCerts: [][]byte{serverLeafDERCert, serverIntermediateDERCert, },
			expectedErr: nil,
		},
	}{
		t.Run(tc.description, func(t *testing.T) {
			// Create new stream to S2Av2.
			opts := []grpc.DialOption {
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithReturnConnectionError(),
				grpc.WithBlock(),
			}
			conn, err := grpc.Dial(address, opts...)
			if err != nil {
				log.Fatalf("Client: failed to connect: %v", err)
			}
			defer conn.Close()
			c := s2av2pb.NewS2AServiceClient(conn)
			log.Printf("Client: connected to: %s", address)
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Setup bidrectional streaming session.
			callOpts := []grpc.CallOption{}
			cstream, err := c.SetUpSession(ctx, callOpts...)
			if err != nil  {
				log.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
			}
			log.Printf("Client: set up bidirectional streaming RPC session.")

			VerifyPeerCertificateFunc := VerifyServerCertificateChain(tc.hostname, cstream)
			got, want := VerifyPeerCertificateFunc(tc.rawCerts, nil), tc.expectedErr
			if want == nil {
				if got != nil {
					t.Errorf("Peer Certificate verification failed, got: %v, want: %v", got, want)
				}
			} else {
				if got == nil {
					t.Errorf("Peer Certificate verification failed, got: %v, want: %v", got, want)
				}
				if got.Error() != want.Error() {
					t.Errorf("Peer Certificate verification failed, got: %v, want: %v", got, want)
				}
			}
		})
	}
	stop()
}
