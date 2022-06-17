package remotesigner

import (
	"net"
	"log"
	"sync"
	"time"
	"bytes"
	"context"
	"testing"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
)

const (
	defaultTimeout = 10.0 * time.Second
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
var (
	//go:embed example_cert_key/cert.pem
	clientCertPEM []byte
	//go:embed example_cert_key/cert.der
	clientCertDER []byte
	//go:embed example_cert_key/key.pem
	clientKeyPEM []byte
)

func TestSign(t *testing.T) {
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		log.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	// Create stream to S2Av2.
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

	// TODO(rmehta19): convert into a for loop when adding more tests.
	// Setup data for testing Sign
	clientTlsCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		log.Fatalf("tls.X509KeyPair failed: %v", err)
	}
	clientx509Cert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		log.Fatalf("failed to parse cert: %v", err)
	}
	s := New(clientx509Cert, cstream, &commonpbv1.Identity {
		IdentityOneof: &commonpbv1.Identity_Hostname {
			Hostname: "client_hostname",
		},
	})
	testInBytes := []byte("Test data.")

	// TODO(rmehta19): Investigate whether go crypto libraries compute hash.
	// If so, remove this line, and just pass testInBytes as digest.
	hsha256 := sha256.Sum256([]byte(testInBytes))
	signerOpts := crypto.SHA256

	// Test Sign.
	gotSignedBytes, err := s.Sign(rand.Reader, hsha256[:], signerOpts)
	if err != nil {
		t.Errorf("call to remote signer Sign API failed: %v", err)
	}
	wantSignedBytes, err := clientTlsCert.PrivateKey.(crypto.Signer).Sign(rand.Reader, hsha256[:], signerOpts)
	if err != nil {
		t.Errorf("call to Sign API failed: %v", err)
	}
	if !bytes.Equal(gotSignedBytes, wantSignedBytes) {
		t.Errorf("gotSignedBytes = %v, wantSignedBytes = %v", gotSignedBytes, wantSignedBytes)
	}
	stop()
}

// TestNew runs unit test for New.
func TestNew(t *testing.T) {
	// Setup data for testing New.
	clientx509Cert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Errorf("failed to parse cert: %v", err)
	}
	localIdentity := &commonpbv1.Identity {
		IdentityOneof: &commonpbv1.Identity_Hostname {
			Hostname: "client_hostname",
		},
	}
	var cstream s2av2pb.S2AService_SetUpSessionClient

	// Test New.
	got := New(clientx509Cert, cstream, localIdentity)
	if v := got.(*remoteSigner).getCert(); v != clientx509Cert {
		t.Errorf("RemoteSigner leafCert field is incorrect. got: %v, want: %v", v, clientx509Cert)
	}
	if v := got.(*remoteSigner).getStream(); v != cstream {
		t.Errorf("RemoteSigner cstream field is incorrect. got: %v, want: %v", v, cstream)
	}
	if v := got.(*remoteSigner).getLocalIdentity(); v != localIdentity {
		t.Errorf("RemoteSigner hostname field is incorrect. got: %v, want: %v", v, localIdentity)
	}
}
