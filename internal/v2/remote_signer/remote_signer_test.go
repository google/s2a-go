package remotesigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultTimeout = 10.0 * time.Second
)

func startFakeS2Av2Server(wg *sync.WaitGroup, expToken string) (stop func(), address string, err error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("failed to listen on address %s: %v", address, err)
	}
	address = listener.Addr().String()
	s := grpc.NewServer()
	log.Printf("Server: started gRPC fake S2Av2 Server on address: %s", address)
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{ExpectedToken: expToken})
	go func() {
		wg.Done()
		if err := s.Serve(listener); err != nil {
			log.Printf("failed to serve: %v", err)
		}
	}()
	return func() { s.Stop() }, address, nil
}

var (
	//go:embed example_cert_key/client_cert.pem
	clientCertPEM []byte
	//go:embed example_cert_key/client_cert.der
	clientCertDER []byte
	//go:embed example_cert_key/client_key.pem
	clientKeyPEM []byte
	//go:embed example_cert_key/server_cert.pem
	serverCertPEM []byte
	//go:embed example_cert_key/server_cert.der
	serverCertDER []byte
	//go:embed example_cert_key/server_key.pem
	serverKeyPEM []byte
)

func TestSign(t *testing.T) {
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg, "TestSign_token")
	wg.Wait()
	if err != nil {
		t.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	for _, tc := range []struct {
		description string
		PEMCert     []byte
		DERCert     []byte
		PEMKey      []byte
		connSide    commonpb.ConnectionSide
	}{
		{
			description: "Sign with client key",
			PEMCert:     clientCertPEM,
			DERCert:     clientCertDER,
			PEMKey:      clientKeyPEM,
			connSide:    commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT,
		},
		{
			description: "Sign with server key",
			PEMCert:     serverCertPEM,
			DERCert:     serverCertDER,
			PEMKey:      serverKeyPEM,
			connSide:    commonpb.ConnectionSide_CONNECTION_SIDE_SERVER,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			// Create stream to S2Av2.
			opts := []grpc.DialOption{
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithReturnConnectionError(),
				grpc.WithBlock(),
			}
			conn, err := grpc.Dial(address, opts...)
			if err != nil {
				t.Fatalf("Client: failed to connect: %v", err)
			}
			defer conn.Close()
			c := s2av2pb.NewS2AServiceClient(conn)
			log.Printf("Client: connected to: %s", address)
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Setup bidrectional streaming session.
			callOpts := []grpc.CallOption{}
			cstream, err := c.SetUpSession(ctx, callOpts...)
			if err != nil {
				t.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
			}
			log.Printf("Client: set up bidirectional streaming RPC session.")
			// Send first SessionReq for TLS Config. Sets isClientSide to ensure correct
			// private key used to sign transcript.
			if err := cstream.Send(&s2av2pb.SessionReq{
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism{
					{
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{
							Token: "TestSign_token",
						},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_GetTlsConfigurationReq{
					GetTlsConfigurationReq: &s2av2pb.GetTlsConfigurationReq{
						ConnectionSide: tc.connSide,
					},
				},
			}); err != nil {
				t.Fatalf("setup failed: failed to send initial SessionReq for TLS config: %v", err)
			}

			if _, err := cstream.Recv(); err != nil {
				t.Fatalf("setup failed: failed to receive initial SessionResp for TLS config: %v", err)
			}
			// Setup data for testing Sign.
			TlsCert, err := tls.X509KeyPair(tc.PEMCert, tc.PEMKey)
			if err != nil {
				t.Fatalf("tls.X509KeyPair failed: %v", err)
			}
			x509Cert, err := x509.ParseCertificate(tc.DERCert)
			if err != nil {
				t.Fatalf("failed to parse cert: %v", err)
			}
			testInBytes := []byte("Test data.")

			// Hash testInBytes because caller of Sign is expected to do so.
			hsha256 := sha256.Sum256([]byte(testInBytes))

			// Test RSA PKCS1v15 signature algorithm.
			s := New(x509Cert, cstream)

			gotSignedBytes, err := s.Sign(rand.Reader, hsha256[:], crypto.SHA256)
			if err != nil {
				t.Errorf("call to remote signer Sign API failed: %v", err)
			}
			wantSignedBytes, err := TlsCert.PrivateKey.(crypto.Signer).Sign(rand.Reader, hsha256[:], crypto.SHA256)
			if err != nil {
				t.Errorf("call to Sign API failed: %v", err)
			}
			if !bytes.Equal(gotSignedBytes, wantSignedBytes) {
				t.Errorf("gotSignedBytes = %v, wantSignedBytes = %v", gotSignedBytes, wantSignedBytes)
			}
			if err = rsa.VerifyPKCS1v15(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hsha256[:], gotSignedBytes); err != nil {
				t.Errorf("failed to verify RSA PKCS #1 v1.5 signature: %v", err)
			}

			// Test RSA PSS signature algorithm.
			s = New(x509Cert, cstream)
			pssSignerOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

			gotSignedBytes, err = s.Sign(rand.Reader, hsha256[:], pssSignerOpts)
			if err = rsa.VerifyPSS(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hsha256[:], gotSignedBytes, pssSignerOpts); err != nil {
				t.Errorf("failed to verify RSA PSS signature: %v", err)
			}
		})
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
	var cstream s2av2pb.S2AService_SetUpSessionClient

	// Test New.
	got := New(clientx509Cert, cstream)
	if v := got.(*remoteSigner).getCert(); v != clientx509Cert {
		t.Errorf("RemoteSigner leafCert field is incorrect. got: %v, want: %v", v, clientx509Cert)
	}
	if v := got.(*remoteSigner).getStream(); v != cstream {
		t.Errorf("RemoteSigner cstream field is incorrect. got: %v, want: %v", v, cstream)
	}
}

// Test GetSignatureAlgorithm runs unit test for getSignatureAlgorithm.
func TestGetSignatureAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		description           string
		opts                  crypto.SignerOpts
		expSignatureAlgorithm s2av2pb.SignatureAlgorithm
	}{
		{
			description:           "RSA PSS SHA256",
			opts:                  &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
			expSignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PSS_RSAE_SHA256,
		},
		{
			description:           "RSA PKCS1 SHA256",
			opts:                  crypto.SHA256,
			expSignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PKCS1_SHA256,
		},
		{
			description:           "UNSPECIFIED",
			opts:                  crypto.SHA1,
			expSignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_UNSPECIFIED,
		},
	} {
		if got, want := getSignatureAlgorithm(tc.opts), tc.expSignatureAlgorithm; got != want {
			t.Errorf("getSignatureAlgorithm(%v): got: %v, want: %v", tc.opts, got, want)
		}
	}
}
