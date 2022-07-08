package remotesigner

import (
	"net"
	"fmt"
	"log"
	"sync"
	"time"
	"bytes"
	"strconv"
	"context"
	"testing"
	"crypto"
	"encoding/pem"
	"crypto/tls"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/sha256"
	_ "embed"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
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
	return func() { s.Stop()}, address, nil
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
	//go:embed example_cert_key/s2a_client_cert.pem
	s2aClientCertPEM []byte
	//go:embed example_cert_key/s2a_client_key.pem
	s2aClientKeyPEM []byte
	//go:embed example_cert_key/s2a_client_cert.der
	s2aClientCertDER []byte
	//go:embed example_cert_key/s2a_server_cert.pem
	s2aServerCertPEM []byte
	//go:embed example_cert_key/s2a_server_key.pem
	s2aServerKeyPEM []byte
	//go:embed example_cert_key/s2a_server_cert.der
	s2aServerCertDER []byte
	//go:embed example_cert_key/openssl_rsa_pkcs1v15.sig
	opensslRSAPKCS1v15Sig []byte
	//go:embed example_cert_key/vector1_pub_key.pem
	vector1PubKeyPEM	      []byte
	//go:embed example_cert_key/vector1_priv_key.pem
	vector1PrivKeyPEM	      []byte
)

func toByteArray(str string) []byte{
	var arr []byte
	for i := 0; i < len(str); i++ {
		s := fmt.Sprintf("%c%c", str[i], str[i+1])
		val, _ := strconv.ParseInt(s, /*base*/16, /*bitsize*/16) // returns a 64 bit integer
		arr = append(arr, byte(uint8(val)))

		i = i + 1
	}
	return arr
}

func TestVerifyVector(t *testing.T) {
	block, _ := pem.Decode(vector1PubKeyPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	vector1 := "840f5dac53106dd1f9c57219224cf51289290c42f20466875ba8e830ac5690e541536fcc8ab03b731f82bf66d83f194e7e180b3963ec7a2f3f7904a7ce49aed47da4d4b79421eaf937d301b3e696169297b797c32c076a12be4de0b58e003c5123051a84a10c62f8dac2f42a8640008eb3c7cccd6760ff5b51b689763922582845f048fb8150e5a7a6ca2eccc7bdc85349ad5b26c52137a79fa3fe5c29ab5cd7615013219c1941b6708e9c3c23feff5febaf0c8ebca5750b54e3e6e99a3e876b396f27860b7f3ec4e9191703c6332d944f6f69751167680c79c4f6b57f1cc8755d24b6ec158ccdbacdb23107a33cb6b332516c13274d1f9dccc21dced869e486"
	vector1ByteArray := toByteArray(vector1)
	testData := ""
	hsha256 := sha256.Sum256([]byte(testData))

	// Test that we can verify vector1 using VerifyPKCS1v15
	if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hsha256[:], vector1ByteArray); err != nil {
		t.Errorf("failed to verify Sign PKCS1v15 RSA PKCS #1 v1.5 signature: %v", err)
	}

	// Test that we can generate vector1 using SignPKCS1v15
	block, _ = pem.Decode(vector1PrivKeyPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block containing private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	expSig, _ := priv.Sign(rand.Reader, hsha256[:], crypto.SHA256)
	if (!bytes.Equal(expSig, vector1ByteArray)) {
		t.Errorf("vector1ByteArray and expSig do not match: expSig = %v, vector1ByteArray = %v", expSig, vector1ByteArray)
	}
}

func TestVerifyOpenSSL(t *testing.T) {
	x509Cert, err := x509.ParseCertificate(s2aClientCertDER)
	if err != nil {
		log.Printf("%v", err)
	}
	testInBytes := []byte("a\n")
	hsha256 := sha256.Sum256([]byte(testInBytes))
	if err = rsa.VerifyPKCS1v15(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hsha256[:], opensslRSAPKCS1v15Sig); err != nil {
		t.Errorf("failed to verify Sign PKCS1v15 RSA PKCS #1 v1.5 signature: %v", err)
	}

}

func TestSign(t *testing.T) {
	// Start up fake S2Av2 server.
	/*var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg, "TestSign_token")
	wg.Wait()
	if err != nil {
		t.Fatalf("error starting fake S2Av2 Server: %v", err)
	} */

	for _, tc := range []struct {
		description	string
		PEMCert		[]byte
		DERCert		[]byte
		PEMKey		[]byte
		connSide	commonpb.ConnectionSide
		localIdentity   *commonpbv1.Identity
		s2aPEMCert	[]byte
		s2aPEMKey	[]byte
		s2aDERCert	[]byte
	}{
		{
			description: "Sign with client key",
			PEMCert: clientCertPEM,
			DERCert: clientCertDER,
			PEMKey: clientKeyPEM,
			connSide: commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT,
			localIdentity: &commonpbv1.Identity{
				IdentityOneof: &commonpbv1.Identity_Hostname{
					Hostname: "test_rsa_client_identity",
				},
			},
			s2aPEMCert: s2aClientCertPEM,
			s2aPEMKey: s2aClientKeyPEM,
			s2aDERCert: s2aClientCertDER,
		},
		{
			description: "Sign with server key",
			PEMCert: serverCertPEM,
			DERCert: serverCertDER,
			PEMKey: serverKeyPEM,
			connSide: commonpb.ConnectionSide_CONNECTION_SIDE_SERVER,
			localIdentity: &commonpbv1.Identity{
				IdentityOneof: &commonpbv1.Identity_Hostname{
					Hostname: "test_rsa_server_identity",
				},
			},
			s2aPEMCert: s2aServerCertPEM,
			s2aPEMKey: s2aServerKeyPEM,
			s2aDERCert: s2aServerCertDER,
		},

	}{
		t.Run(tc.description, func(t *testing.T) {
			// Create stream to S2Av2.
			opts := []grpc.DialOption {
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithReturnConnectionError(),
				grpc.WithBlock(),
			}
			conn, err := grpc.Dial("0.0.0.0:61365", opts...)
			if err != nil {
				t.Fatalf("Client: failed to connect: %v", err)
			}
			defer conn.Close()
			c := s2av2pb.NewS2AServiceClient(conn)
			log.Printf("Client: connected to: 0.0.0.0:61365")
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Setup bidrectional streaming session.
			callOpts := []grpc.CallOption{}
			cstream, err := c.SetUpSession(ctx, callOpts...)
			if err != nil  {
				t.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
			}
			log.Printf("Client: set up bidirectional streaming RPC session.")
			// Send first SessionReq for TLS Config. Sets isClientSide to ensure correct
			// private key used to sign transcript.
			if err := cstream.Send(&s2av2pb.SessionReq {
				LocalIdentity: tc.localIdentity,
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token {
							Token: "fake_valid_access_token",
						},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_GetTlsConfigurationReq {
					&s2av2pb.GetTlsConfigurationReq {
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
			testInBytes := []byte("a\n")
			x509Cert, _ := x509.ParseCertificate(tc.s2aDERCert)
			pssSignerOpts := &rsa.PSSOptions {SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256 }

			// Hash testInBytes because caller of Sign is expected to do so.
			hsha256 := sha256.Sum256([]byte(testInBytes))

			// Test RSA PSS
			// Ask S2A for RSA PSS signature.
			cstream.Send(&s2av2pb.SessionReq {
				ReqOneof: &s2av2pb.SessionReq_OffloadPrivateKeyOperationReq {
					&s2av2pb.OffloadPrivateKeyOperationReq {
						Operation: s2av2pb.OffloadPrivateKeyOperationReq_SIGN,
						SignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PSS_RSAE_SHA256,
						InBytes: hsha256[:],
					},
				},
			})


			// Get the response from S2Av2.
			resp, _ := cstream.Recv()
			log.Printf("S2A: RSA PSS SHA256 outbytes: %x", resp.GetOffloadPrivateKeyOperationResp().GetOutBytes())

			if err = rsa.VerifyPSS(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hsha256[:], resp.GetOffloadPrivateKeyOperationResp().GetOutBytes(), pssSignerOpts); err != nil {
				t.Errorf("failed to verify S2A RSA PSS signature: %v", err)
			}

			// Generate RSA PSS Signature using crypto/rsa SignPSS
			TlsCert, _ := tls.X509KeyPair(tc.s2aPEMCert, tc.s2aPEMKey)
			expSig, _ := TlsCert.PrivateKey.(crypto.Signer).Sign(rand.Reader, hsha256[:], pssSignerOpts)
			log.Printf("expSig: RSA PSS SHA256 outbytes: %x", expSig)

			if err = rsa.VerifyPSS(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hsha256[:], expSig, pssSignerOpts); err != nil {
				t.Errorf("failed to verify Sign PSS RSA PSS signature: %v", err)
			}

			// Test RSA PKCS1v15
			// Ask S2A for RSA PKCS1v15 signature
			cstream.Send(&s2av2pb.SessionReq {
				ReqOneof: &s2av2pb.SessionReq_OffloadPrivateKeyOperationReq {
					&s2av2pb.OffloadPrivateKeyOperationReq {
						Operation: s2av2pb.OffloadPrivateKeyOperationReq_SIGN,
						SignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PKCS1_SHA256,
						InBytes: hsha256[:],
					},
				},
			})

			resp, _ = cstream.Recv()
			log.Printf("RSA PKCS1v15 SHA256 outbytes: %v", resp.GetOffloadPrivateKeyOperationResp().GetOutBytes())

			if err = rsa.VerifyPKCS1v15(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hsha256[:], resp.GetOffloadPrivateKeyOperationResp().GetOutBytes()); err != nil {
				t.Errorf("failed to verify S2A RSA PKCS #1 v1.5 signature: %v", err)
			}

			// Generate RSA PKCS1v15 signature using crypto/rsa SignPKCS1v15
			TlsCert, _ = tls.X509KeyPair(tc.s2aPEMCert, tc.s2aPEMKey)
			expSig, _ = TlsCert.PrivateKey.(crypto.Signer).Sign(rand.Reader, hsha256[:], crypto.SHA256)
			log.Printf("expSig: RSA PKCS1v15 SHA256 outbytes: %x", expSig)

			if err = rsa.VerifyPKCS1v15(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hsha256[:], expSig); err != nil {
				t.Errorf("failed to verify Sign PKCS1v15 RSA PKCS #1 v1.5 signature: %v", err)
			}

		})
	}
	//	stop()
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
		description string
		opts crypto.SignerOpts
		expSignatureAlgorithm s2av2pb.SignatureAlgorithm
	} {
		{
			description: "RSA PSS SHA256",
			opts: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
			expSignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PSS_RSAE_SHA256,
		},
		{
			description: "RSA PKCS1 SHA256",
			opts: crypto.SHA256,
			expSignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PKCS1_SHA256,
		},
		{
			description: "UNSPECIFIED",
			opts: crypto.SHA1,
			expSignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_UNSPECIFIED,
		},
	} {
		if got, want := getSignatureAlgorithm(tc.opts), tc.expSignatureAlgorithm; got != want {
			t.Errorf("getSignatureAlgorithm(%v): got: %v, want: %v", tc.opts, got, want)
		}
	}
}
