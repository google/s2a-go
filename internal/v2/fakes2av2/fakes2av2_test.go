package fakes2av2

import (
	"net"
	"log"
	"fmt"
	"time"
	"sync"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"context"
	"testing"
	"google.golang.org/grpc"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/testing/protocmp"

	s2av2ctx "github.com/google/s2a-go/internal/proto/v2/s2a_context_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
)

const (
	defaultTimeout = 10.0 * time.Second
)

func startFakeS2Av2Server(wg *sync.WaitGroup) (address string, stop func(), err error) {
	// Pick unused port.
	listener, err := net.Listen("tcp", ":0")
	address = listener.Addr().String()
	if err != nil {
		log.Fatalf("failed to listen on address %s: %v", listener.Addr().String(), err)
	}
	s := grpc.NewServer()
	log.Printf("Server: started gRPC Fake S2Av2 Server on address: %s", listener.Addr().String())
	s2av2pb.RegisterS2AServiceServer(s, &Server{})
	go func() {
		wg.Done()
		if err := s.Serve(listener); err != nil {
			log.Printf("failed to serve: %v", err)
		}
	}()
	return address, func() { s.Stop()}, nil
}

func TestSetUpSession(t *testing.T) {
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	address, stop, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		log.Fatalf("failed to set up fake S2Av2 server.")
	}

	// Setup for client and server offloadPrivateKeyOperation test.
	clientTlsCert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		log.Fatalf("failed during test setup: %v", err)
	}

	serverTlsCert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatalf("failed during test setup: %v", err)
	}

	testString := "Generate hash and sign this."

	// TODO(rmehta19): Investigate whether go crypto libraries compute hash.
	// If so, remove this line, and just pass testString to Sign and as InBytes.
	hsha256 := sha256.Sum256([]byte(testString))

	var opts crypto.Hash = crypto.SHA256
	signedWithClientKey, err := clientTlsCert.PrivateKey.(crypto.Signer).Sign(rand.Reader, hsha256[:], opts)
	if err != nil {
		log.Fatalf("failed during test setup: %v", err)
	}
	signedWithServerKey, err := serverTlsCert.PrivateKey.(crypto.Signer).Sign(rand.Reader, hsha256[:], opts)
	if err != nil {
		log.Fatalf("failed during test setup: %v", err)
	}

	for _, tc := range []struct {
		description		string
		request			*s2av2pb.SessionReq
		expectedResponse	*s2av2pb.SessionResp
	}{
		{
			description: "Get TLS config for client.",
			request: &s2av2pb.SessionReq {
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_GetTlsConfigurationReq {
					&s2av2pb.GetTlsConfigurationReq {
						ConnectionSide: commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT,
					},
				},
			},
			expectedResponse: &s2av2pb.SessionResp {
				Status: &s2av2pb.Status {
					Code: 0,
				},
				RespOneof: &s2av2pb.SessionResp_GetTlsConfigurationResp {
					GetTlsConfigurationResp: &s2av2pb.GetTlsConfigurationResp {
						TlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration_ {
							&s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration {
								CertificateChain: []string{
									string(clientCert),
								},
								MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
								MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
								HandshakeCiphersuites: []commonpb.HandshakeCiphersuite{},
								RecordCiphersuites: []commonpb.RecordCiphersuite {
									commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_128_GCM_SHA256,
									commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_256_GCM_SHA384,
									commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_CHACHA20_POLY1305_SHA256,
								},
							},
						},
					},
				},
			},
		},
		{
			description: "Get TLS config for server.",
			request: &s2av2pb.SessionReq {
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_GetTlsConfigurationReq {
					&s2av2pb.GetTlsConfigurationReq {
						ConnectionSide: commonpb.ConnectionSide_CONNECTION_SIDE_SERVER,
					},
				},
			},
			expectedResponse: &s2av2pb.SessionResp {
				Status: &s2av2pb.Status {
					Code: 0,
				},
				RespOneof: &s2av2pb.SessionResp_GetTlsConfigurationResp {
					GetTlsConfigurationResp: &s2av2pb.GetTlsConfigurationResp {
						TlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_{
							&s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
								CertificateChain: []string{
									string(serverCert),
								},
								MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
								MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
								HandshakeCiphersuites: []commonpb.HandshakeCiphersuite{},
								RecordCiphersuites: []commonpb.RecordCiphersuite {
									commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_128_GCM_SHA256,
									commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_256_GCM_SHA384,
									commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_CHACHA20_POLY1305_SHA256,
								},
								TlsResumptionEnabled: false,
								RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_AND_VERIFY,
								MaxOverheadOfTicketAead: 0,
							},
						},
					},
				},
			},
		},
		{
			description: "Client Peer Verification",
			request: &s2av2pb.SessionReq {
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						// TODO(rmehta19): Populate Authentication Mechanism using tokenmanager.
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_ValidatePeerCertificateChainReq {
					&s2av2pb.ValidatePeerCertificateChainReq {
						Mode: s2av2pb.ValidatePeerCertificateChainReq_SPIFFE,
						PeerOneof: &s2av2pb.ValidatePeerCertificateChainReq_ClientPeer_ {
							&s2av2pb.ValidatePeerCertificateChainReq_ClientPeer {
								CertificateChain: [][]byte{clientDERCert,},
							},
						},
					},
				},
			},
			expectedResponse: &s2av2pb.SessionResp {
				Status: &s2av2pb.Status {
					Code: 0,
					Details: "",
				},
				RespOneof: &s2av2pb.SessionResp_ValidatePeerCertificateChainResp {
					&s2av2pb.ValidatePeerCertificateChainResp {
						ValidationResult: s2av2pb.ValidatePeerCertificateChainResp_SUCCESS,
						ValidationDetails: "Client Peer Verification succeeded",
						Context: &s2av2ctx.S2AContext{},
					},
				},
			},
		},
		{
			description: "Server Peer Verification",
			request: &s2av2pb.SessionReq {
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						// TODO(rmehta19): Populate Authentication Mechanism using tokenmanager.
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_ValidatePeerCertificateChainReq {
					&s2av2pb.ValidatePeerCertificateChainReq {
						Mode: s2av2pb.ValidatePeerCertificateChainReq_SPIFFE,
						PeerOneof: &s2av2pb.ValidatePeerCertificateChainReq_ServerPeer_ {
							&s2av2pb.ValidatePeerCertificateChainReq_ServerPeer {
								CertificateChain: [][]byte{serverDERCert,},
							},
						},
					},
				},
			},
			expectedResponse: &s2av2pb.SessionResp {
				Status: &s2av2pb.Status {
					Code: 0,
					Details: "",
				},
				RespOneof: &s2av2pb.SessionResp_ValidatePeerCertificateChainResp {
					&s2av2pb.ValidatePeerCertificateChainResp {
						ValidationResult: s2av2pb.ValidatePeerCertificateChainResp_SUCCESS,
						ValidationDetails: "Server Peer Verification succeeded",
						Context: &s2av2ctx.S2AContext{},
					},
				},
			},
		},
		{
			description: "client side private key operation",
			request: &s2av2pb.SessionReq {
				LocalIdentity: &commonpbv1.Identity {
					IdentityOneof: &commonpbv1.Identity_Hostname {
						Hostname: "client_hostname",
					},
				},
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						// TODO(rmehta19): Populate Authentication Mechanism using tokenmanager.
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_OffloadPrivateKeyOperationReq {
					&s2av2pb.OffloadPrivateKeyOperationReq {
						Operation: s2av2pb.OffloadPrivateKeyOperationReq_SIGN,
						SignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PKCS1_SHA256,
						InBytes: []byte(hsha256[:]),
					},
				},
			},
			expectedResponse: &s2av2pb.SessionResp {
				Status: &s2av2pb.Status {
					Code: 0,
				},
				RespOneof: &s2av2pb.SessionResp_OffloadPrivateKeyOperationResp {
					&s2av2pb.OffloadPrivateKeyOperationResp {
						OutBytes: signedWithClientKey,
					},
				},
			},
		},
		{
			description: "server side private key operation",
			request: &s2av2pb.SessionReq {
				LocalIdentity: &commonpbv1.Identity {
					IdentityOneof: &commonpbv1.Identity_Hostname {
						Hostname: "server_hostname",
					},
				},
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						// TODO(rmehta19): Populate Authentication Mechanism using tokenmanager.
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_OffloadPrivateKeyOperationReq {
					&s2av2pb.OffloadPrivateKeyOperationReq {
						Operation: s2av2pb.OffloadPrivateKeyOperationReq_SIGN,
						SignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PKCS1_SHA256,
						InBytes: []byte(hsha256[:]),
					},
				},
			},
			expectedResponse: &s2av2pb.SessionResp {
				Status: &s2av2pb.Status {
					Code: 0,
				},
				RespOneof: &s2av2pb.SessionResp_OffloadPrivateKeyOperationResp {
					&s2av2pb.OffloadPrivateKeyOperationResp {
						OutBytes: signedWithServerKey,
					},
				},
			},
		},
		{
			description: "client side private key operation -- error",
			request: &s2av2pb.SessionReq {
				LocalIdentity: &commonpbv1.Identity {
					IdentityOneof: &commonpbv1.Identity_Hostname {
						Hostname: "client_hostname",
					},
				},
				AuthenticationMechanisms: []*s2av2pb.AuthenticationMechanism {
					{
						// TODO(rmehta19): Populate Authentication Mechanism using tokenmanager.
						MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{"token"},
					},
				},
				ReqOneof: &s2av2pb.SessionReq_OffloadPrivateKeyOperationReq {
					&s2av2pb.OffloadPrivateKeyOperationReq {
						Operation: s2av2pb.OffloadPrivateKeyOperationReq_SIGN,
						SignatureAlgorithm: s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_UNSPECIFIED,
						InBytes: []byte(hsha256[:]),
					},
				},
			},
			expectedResponse: &s2av2pb.SessionResp {
				Status: &s2av2pb.Status {
					Code: 3,
					Details: fmt.Sprintf("invalid signature algorithm: %v", s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_UNSPECIFIED),
				},
			},
		},
	}{
		t.Run(tc.description, func(t *testing.T) {
			// Create new stream to server.
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
			if err != nil  {
				t.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
			}
			log.Printf("Client: set up bidirectional streaming RPC session.")

			// Send request.
			if err := cstream.Send(tc.request); err != nil {
				t.Fatalf("Client: failed to send SessionReq: %v", err)
			}
			log.Printf("Client: sent SessionReq")

			// Get the response.
			resp, err := cstream.Recv()
			if err != nil {
				t.Fatalf("Client: failed to receive SessionResp: %v", err)
			}
			log.Printf("Client: recieved SessionResp")
			if diff := cmp.Diff(resp, tc.expectedResponse, protocmp.Transform()); diff != "" {
				t.Errorf("cstream.Recv() returned incorrect SessionResp, (-want +got):\n%s", diff)
			}
			log.Printf("resp matches tc.expectedResponse")
		})
	}
	stop()
}
