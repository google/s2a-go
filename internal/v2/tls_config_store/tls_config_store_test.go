package tlsconfigstore

import (
	"net"
	"fmt"
	"log"
	"sync"
	"time"
	"context"
	"testing"
	"crypto/tls"
	"bytes"

	_ "embed"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	"github.com/google/s2a-go/internal/tokenmanager"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
)

const (
	defaultTimeout = 10.0 * time.Second
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

// fakeAccessTokenManager implements the AccessTokenManager interface.
type fakeAccessTokenManager struct {
	acceptedIdentity   *commonpbv1.Identity
	accessToken        string
	allowEmptyIdentity bool
}

// DefaultToken returns the token managed by the fakeAccessTokenManager.
func (m *fakeAccessTokenManager) DefaultToken() (string, error) {
	if !m.allowEmptyIdentity {
		return "", fmt.Errorf("not allowed to get token for empty identity")
	}
	return m.accessToken, nil
}

// Token returns the token managed by the fakeAccessTokenManager.
func (m *fakeAccessTokenManager) Token(identity *commonpbv1.Identity) (string, error) {
	if identity == nil || cmp.Equal(identity, &commonpbv1.Identity{}, protocmp.Transform()) {
		if !m.allowEmptyIdentity {
			return "", fmt.Errorf("not allowed to get token for empty identity")
		}
		return m.accessToken, nil
	}
	if cmp.Equal(identity, m.acceptedIdentity, protocmp.Transform()) {
		return m.accessToken, nil
	}
	return "", fmt.Errorf("unable to get token")
}

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

// TODO(rmehta19): In Client and Server test, verify contents of config.RootCAs once x509.CertPool.Equal function is officially released : https://cs.opensource.google/go/go/+/4aacb7ff0f103d95a724a91736823f44aa599634 .

// TestTLSConfigStoreClient runs unit tests for GetTlsConfigurationForClient.
func TestTLSConfigStoreClient(t *testing.T) {
	// Setup for static client test.
	cert, err := tls.X509KeyPair(clientCertpem, clientKeypem)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}

	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		t.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	accessTokenManager := &fakeAccessTokenManager{
		accessToken: "TestTLSConfigStoreClient_s2a_access_token",
		allowEmptyIdentity: true,
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
			// Create stream to S2Av2.
			opts := []grpc.DialOption {
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
			config, err := GetTlsConfigurationForClient(tc.ServerName, cstream, accessTokenManager, nil)
			if err != nil {
				t.Errorf("GetTlsConfigurationForClient failed: %v", err)
			}
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
	stop()
}

// TestTLSConfigStoreServer runs unit tests for GetTLSConfigurationForServer.
func TestTLSConfigStoreServer(t *testing.T) {
	// Setup for static server test.
	cert, err := tls.X509KeyPair(serverCertpem, serverKeypem)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		t.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	accessTokenManager := &fakeAccessTokenManager{
		accessToken: "TestTLSConfigStoreServer_s2a_access_token",
		allowEmptyIdentity: true,
	}
	var identities [] *commonpbv1.Identity
	identities = append(identities, nil)
	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		ClientAuth		    tls.ClientAuthType
		MinVersion	            uint16
		MaxVersion		    uint16
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAnyClientCert,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			// Create stream to S2Av2.
			opts := []grpc.DialOption {
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
			config, err := GetTlsConfigurationForServer(cstream, accessTokenManager, identities)
			if err != nil {
				t.Errorf("GetTlsConfigurationForClient failed: %v", err)
			}
			clientConfigFunc := config.GetConfigForClient
			config, err = clientConfigFunc(&tls.ClientHelloInfo{
				ServerName: "host_1",
			})
			if err != nil {
				t.Errorf("ClientConfig failed: %v", err)
			}
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got,want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			if got, want := config.ClientAuth, tc.ClientAuth; got != want {
				t.Errorf("config.ClientAuth = %v, want %v", got, want)
			}
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
		})
	}
	stop()
}

func TestGetTLSMinMaxVersionsClient(t *testing.T) {
	m := makeMapOfTLSVersions()
	for min := commonpb.TLSVersion_TLS_VERSION_1_0; min <= commonpb.TLSVersion_TLS_VERSION_1_3; min++ {
		for max := commonpb.TLSVersion_TLS_VERSION_1_0; max <= commonpb.TLSVersion_TLS_VERSION_1_3; max++ {
			tlsConfig := &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration {
				MinTlsVersion: min,
				MaxTlsVersion: max,
			}
			tlsMin, tlsMax, err := getTLSMinMaxVersionsServer(tlsConfig)
			if err != nil {
				if min <= max {
					t.Errorf("err = %v, expected err = nil", err)
				} else {
					if m[min] != tlsMin {
						t.Errorf("tlsMin = %v, expected %v", tlsMin, m[min])
					}
					if m[max] != tlsMax {
						t.Errorf("tlsMax = %v, expected %v", tlsMax, m[max])
					}
				}
			} else {
				if min > max {
					t.Errorf("err = nil, expected err = S2Av2 provided minVersion > maxVersion.")
				} else {
					if m[min] != tlsMin {
						t.Errorf("tlsMin = %v, expected %v", tlsMin, m[min])
					}
					if m[max] != tlsMax {
						t.Errorf("tlsMax = %v, expected %v", tlsMax, m[max])
					}
				}
			}
		}
	}
	// Test invalid input.
	tlsConfig := &s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration {
		MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_0 - 1,
		MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
	}
	expErr := fmt.Errorf("S2Av2 provided invalid MinTlsVersion: %v", tlsConfig.MinTlsVersion)
	_, _, err := getTLSMinMaxVersionsClient(tlsConfig)
	if (err == nil) || (err.Error() != expErr.Error()){
		t.Errorf("err = %v, expErr = %v", err, expErr)
	}

	tlsConfig = &s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration {
		MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_0,
		MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3 + 1,
	}
	expErr = fmt.Errorf("S2Av2 provided invalid MaxTlsVersion: %v", tlsConfig.MaxTlsVersion)
	_, _, err = getTLSMinMaxVersionsClient(tlsConfig)
	if (err == nil) || (err.Error() != expErr.Error()){
		t.Errorf("err = %v, expErr = %v", err, expErr)
	}
}

func TestGetTLSMinMaxVersionsServer(t *testing.T) {
	m := makeMapOfTLSVersions()
	for min := commonpb.TLSVersion_TLS_VERSION_1_0; min <= commonpb.TLSVersion_TLS_VERSION_1_3; min++ {
		for max := commonpb.TLSVersion_TLS_VERSION_1_0; max <= commonpb.TLSVersion_TLS_VERSION_1_3; max++ {
			tlsConfig := &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration {
				MinTlsVersion: min,
				MaxTlsVersion: max,
			}
			tlsMin, tlsMax, err := getTLSMinMaxVersionsServer(tlsConfig)
			if err != nil {
				if min <= max {
					t.Errorf("err = %v, expected err = nil", err)
				} else {
					if m[min] != tlsMin {
						t.Errorf("tlsMin = %v, expected %v", tlsMin, m[min])
					}
					if m[max] != tlsMax {
						t.Errorf("tlsMax = %v, expected %v", tlsMax, m[max])
					}
				}
			} else {
				if min > max {
					t.Errorf("err = nil, expected err = S2Av2 provided minVersion > maxVersion.")
				} else {
					if m[min] != tlsMin {
						t.Errorf("tlsMin = %v, expected %v", tlsMin, m[min])
					}
					if m[max] != tlsMax {
						t.Errorf("tlsMax = %v, expected %v", tlsMax, m[max])
					}
				}
			}
		}
	}

	// Test invalid input.
	tlsConfig := &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration {
		MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_0 - 1,
		MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
	}
	expErr := fmt.Errorf("S2Av2 provided invalid MinTlsVersion: %v", tlsConfig.MinTlsVersion)
	_, _, err := getTLSMinMaxVersionsServer(tlsConfig)
	if (err == nil) || (err.Error() !=  expErr.Error()){
		t.Errorf("err = %v, expErr = %v", err, expErr)
	}

	tlsConfig = &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration {
		MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_0,
		MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3 + 1,
	}
	expErr = fmt.Errorf("S2Av2 provided invalid MaxTlsVersion: %v", tlsConfig.MaxTlsVersion)
	_, _, err = getTLSMinMaxVersionsServer(tlsConfig)
	if (err == nil) || (err.Error() != expErr.Error()) {
		t.Errorf("err = %v, expErr = %v", err, expErr)
	}
}

func TestGetAuthMechanisms(t *testing.T) {
	// Setup data for test.
	sortProtos := cmpopts.SortSlices(func(m1, m2 *s2av2pb.AuthenticationMechanism) bool { return m1.String() < m2.String() })

	// TODO(rmehta19): Add additional tests.
	for _, tc := range []struct {
		description string
		tokenManager tokenmanager.AccessTokenManager
		localIdentities []*commonpbv1.Identity
		expectedAuthMechanisms []*s2av2pb.AuthenticationMechanism
	}{
		{
			description: "token manager is nil",
			tokenManager: nil,
			expectedAuthMechanisms: nil,
		},
		{
			description: "token manager expects empty identity",
			tokenManager: &fakeAccessTokenManager{
				accessToken:        "TestGetAuthMechanisms_s2a_access_token",
				allowEmptyIdentity: true,
			},
			expectedAuthMechanisms: []*s2av2pb.AuthenticationMechanism{
				&s2av2pb.AuthenticationMechanism{
					MechanismOneof: &s2av2pb.AuthenticationMechanism_Token{
						Token: "TestGetAuthMechanisms_s2a_access_token",
					},
				},
			},
		},
		{
			description: "token manager does not expect empty identity",
			tokenManager: &fakeAccessTokenManager{
				allowEmptyIdentity: false,
			},
			expectedAuthMechanisms: nil,
		},

	} {
		t.Run(tc.description, func(t *testing.T) {
			authMechanisms := getAuthMechanisms(tc.tokenManager, tc.localIdentities)
			if got, want := (authMechanisms == nil), (tc.expectedAuthMechanisms == nil); got != want {
				t.Errorf("authMechanisms == nil: %t, tc.expectedAuthMechanisms == nil: %t", got, want)
			}
			if authMechanisms != nil && tc.expectedAuthMechanisms != nil {
				if diff := cmp.Diff(authMechanisms, tc.expectedAuthMechanisms, protocmp.Transform(), sortProtos); diff != "" {
					t.Errorf("getAuthMechanisms(%v, %v) returned incorrect slice, (-want +got):\n%s", tc.tokenManager, tc.localIdentities, diff)
				}
			}
		})
	}
}
func TestGetServerConfigFromS2Av2(t *testing.T) {
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		t.Fatalf("error starting fake S2Av2 Server: %v", err)
	}
	for _, tc := range []struct {
		description string
		tokenManager tokenmanager.AccessTokenManager
		localIdentities []*commonpbv1.Identity
		expTlsConfig *s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration
		expErr error
	} {
		{
			description: "empty localIdentities",
			tokenManager: &fakeAccessTokenManager{
				allowEmptyIdentity: true,
			},
			localIdentities: nil,
			expTlsConfig: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
								CertificateChain: []string{
									string(serverCertpem),
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
								RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY,
								MaxOverheadOfTicketAead: 0,
							},
			expErr: nil,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			// Create stream to S2Av2.
			opts := []grpc.DialOption {
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
			gotTlsConfig, gotErr := getServerConfigFromS2Av2(tc.tokenManager, tc.localIdentities, cstream)
			if gotErr != tc.expErr {
				t.Errorf("gotErr = %v,  tc.expErr = %v", gotErr, tc.expErr)
			}
			if diff := cmp.Diff(gotTlsConfig, tc.expTlsConfig, protocmp.Transform()); diff != "" {
				t.Errorf("getServerConfigFromS2Av2 returned incorrect GetTlsConfigurationResp_ServerTlsConfiguration, (-want +got):\n%s", diff)
			}
		})
	}
	stop()
}

func TestGetClientConfig(t *testing.T) {
	// Setup test.
	cert, err := tls.X509KeyPair(serverCertpem, serverKeypem)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}
	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, address, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		t.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	accessTokenManager := &fakeAccessTokenManager{
		accessToken: "TestTLSConfigStoreServer_s2a_access_token",
		allowEmptyIdentity: true,
	}
	var identities [] *commonpbv1.Identity
	identities = append(identities, nil)
	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		ClientAuth		    tls.ClientAuthType
		MinVersion	            uint16
		MaxVersion		    uint16
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAnyClientCert,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			// Create stream to S2Av2.
			opts := []grpc.DialOption {
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
			clientConfigFunc := ClientConfig(accessTokenManager, identities, cstream)
			config, err := clientConfigFunc(&tls.ClientHelloInfo{
				ServerName: "host_1",
			})
			if err != nil {
				t.Errorf("ClientConfig failed: %v", err)
			}
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got,want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			if got, want := config.ClientAuth, tc.ClientAuth; got != want {
				t.Errorf("config.ClientAuth = %v, want %v", got, want)
			}
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
		})
	}
	stop()
}

func TestGetTLSClientAuthType(t *testing.T) {
	for _, tc := range []struct {
		description string
		tlsConfig *s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration
		expClientAuthType tls.ClientAuthType
	} {
		{
			description: "Don't request client cert",
			tlsConfig: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
				RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_DONT_REQUEST_CLIENT_CERTIFICATE,
			},
			expClientAuthType: tls.NoClientCert,
		},
		{
			description: "Request client cert, but don't verify",
			tlsConfig: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
				RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY,
			},
			expClientAuthType: tls.RequestClientCert,
		},
		{
			description: "Request client cert and verify",
			tlsConfig: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
				RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY,
			},
			expClientAuthType: tls.RequireAnyClientCert,
		},
		{
			description: "Request and Require client cert, but don't verify",
			tlsConfig: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
				RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_BUT_DONT_VERIFY,
			},
			expClientAuthType: tls.RequireAnyClientCert,
		},
		{
			description: "Request and Require client cert and verify",
			tlsConfig: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
				RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY,
			},
			expClientAuthType: tls.RequireAnyClientCert,
		},
		{
			description: "default case",
			tlsConfig: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
				RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_UNSPECIFIED,
			},
			expClientAuthType: tls.RequireAnyClientCert,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			if got, want := getTLSClientAuthType(tc.tlsConfig), tc.expClientAuthType; got != want {
				t.Errorf("getClientAuthType(%v) returned %v, want = %v", tc.tlsConfig, got, want)
			}
		})
	}
}

func makeMapOfTLSVersions() map[commonpb.TLSVersion]uint16 {
	m := make(map[commonpb.TLSVersion]uint16)
	m[commonpb.TLSVersion_TLS_VERSION_1_0] = tls.VersionTLS10
	m[commonpb.TLSVersion_TLS_VERSION_1_1] = tls.VersionTLS11
	m[commonpb.TLSVersion_TLS_VERSION_1_2] = tls.VersionTLS12
	m[commonpb.TLSVersion_TLS_VERSION_1_3] = tls.VersionTLS13
	return m
}
