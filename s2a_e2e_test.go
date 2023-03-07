/*
 *
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package s2a

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "embed"

	"github.com/google/s2a-go/fallback"
	"github.com/google/s2a-go/internal/fakehandshaker/service"
	commonpb "github.com/google/s2a-go/internal/proto/common_go_proto"
	helloworldpb "github.com/google/s2a-go/internal/proto/examples/helloworld_go_proto"
	s2apb "github.com/google/s2a-go/internal/proto/s2a_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/peer"
)

const (
	accessTokenEnvVariable = "S2A_ACCESS_TOKEN"
	testAccessToken        = "test_access_token"
	testV2AccessToken      = "valid_token"

	applicationProtocol   = "grpc"
	authType              = "s2a"
	clientHostname        = "test_client_hostname"
	serverSpiffeID        = "test_server_spiffe_id"
	clientMessage         = "echo"
	defaultE2ETestTimeout = time.Second * 5
)

var (
	//go:embed internal/v2/tlsconfigstore/example_cert_key/client_cert.pem
	clientCertpem []byte
	//go:embed internal/v2/tlsconfigstore/example_cert_key/client_key.pem
	clientKeypem []byte
	//go:embed internal/v2/tlsconfigstore/example_cert_key/server_cert.pem
	serverCertpem []byte
	//go:embed internal/v2/tlsconfigstore/example_cert_key/server_key.pem
	serverKeypem []byte
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	helloworldpb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer.
func (s *server) SayHello(_ context.Context, in *helloworldpb.HelloRequest) (*helloworldpb.HelloReply, error) {
	return &helloworldpb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

// startFakeS2A starts up a fake S2A and returns the address that it is
// listening on.
func startFakeS2A(t *testing.T, enableV2 bool, expToken string) string {
	lis, err := net.Listen("tcp", ":")
	if err != nil {
		t.Errorf("net.Listen(tcp, :0) failed: %v", err)
	}
	s := grpc.NewServer()
	if enableV2 {
		s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{ExpectedToken: expToken})
	} else {
		s2apb.RegisterS2AServiceServer(s, &service.FakeHandshakerService{})
	}
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

// startFakeS2AOnUDS starts up a fake S2A on UDS and returns the address that
// it is listening on.
func startFakeS2AOnUDS(t *testing.T, enableV2 bool, expToken string) string {
	dir, err := ioutil.TempDir("/tmp", "socket_dir")
	if err != nil {
		t.Errorf("Unable to create temporary directory: %v", err)
	}
	udsAddress := filepath.Join(dir, "socket")
	lis, err := net.Listen("unix", filepath.Join(dir, "socket"))
	if err != nil {
		t.Errorf("net.Listen(unix, %s) failed: %v", udsAddress, err)
	}
	s := grpc.NewServer()
	if enableV2 {
		s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{ExpectedToken: expToken})
	} else {
		s2apb.RegisterS2AServiceServer(s, &service.FakeHandshakerService{})
	}
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return fmt.Sprintf("unix://%s", lis.Addr().String())
}

// startServer starts up a server and returns the address that it is listening
// on.
func startServer(t *testing.T, s2aAddress string, enableV2 bool) string {
	serverOpts := &ServerOptions{
		LocalIdentities: []Identity{NewSpiffeID(serverSpiffeID)},
		S2AAddress:      s2aAddress,
		EnableV2:        enableV2,
	}
	creds, err := NewServerCreds(serverOpts)
	if err != nil {
		t.Errorf("NewServerCreds(%v) failed: %v", serverOpts, err)
	}

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Errorf("net.Listen(tcp, :0) failed: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	helloworldpb.RegisterGreeterServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

// runClient starts up a client and calls the server.
func runClient(ctx context.Context, t *testing.T, clientS2AAddress, serverAddr string, enableV2 bool) {
	clientOpts := &ClientOptions{
		TargetIdentities: []Identity{NewSpiffeID(serverSpiffeID)},
		LocalIdentity:    NewHostname(clientHostname),
		S2AAddress:       clientS2AAddress,
		EnableV2:         enableV2,
	}
	creds, err := NewClientCreds(clientOpts)
	if err != nil {
		t.Errorf("NewClientCreds(%v) failed: %v", clientOpts, err)
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	}

	grpclog.Info("Client dialing server at address: %v", serverAddr)
	// Establish a connection to the server.
	conn, err := grpc.Dial(serverAddr, dialOptions...)
	if err != nil {
		t.Errorf("grpc.Dial(%v, %v) failed: %v", serverAddr, dialOptions, err)
	}
	defer conn.Close()

	// Contact the server.
	peer := new(peer.Peer)
	c := helloworldpb.NewGreeterClient(conn)
	req := &helloworldpb.HelloRequest{Name: clientMessage}
	grpclog.Infof("Client calling SayHello with request: %v", req)
	resp, err := c.SayHello(ctx, req, grpc.Peer(peer), grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("c.SayHello(%v, %v) failed: %v", ctx, req, err)
	}
	if got, want := resp.GetMessage(), "Hello "+clientMessage; got != want {
		t.Errorf("r.GetMessage() = %v, want %v", got, want)
	}
	grpclog.Infof("Client received message from server: %s", resp.GetMessage())

	if !enableV2 {
		// Check the auth info.
		authInfo, err := AuthInfoFromPeer(peer)
		if err != nil {
			t.Errorf("AuthInfoFromContext(peer) failed: %v", err)
		}
		s2aAuthInfo, ok := authInfo.(AuthInfo)
		if !ok {
			t.Errorf("authInfo is not an s2a.AuthInfo")
		}
		if got, want := s2aAuthInfo.AuthType(), authType; got != want {
			t.Errorf("s2aAuthInfo.AuthType() = %v, want %v", got, want)
		}
		if got, want := s2aAuthInfo.ApplicationProtocol(), applicationProtocol; got != want {
			t.Errorf("s2aAuthInfo.ApplicationProtocol() = %v, want %v", got, want)
		}
		if got, want := s2aAuthInfo.TLSVersion(), commonpb.TLSVersion_TLS1_3; got != want {
			t.Errorf("s2aAuthInfo.TLSVersion() = %v, want %v", got, want)
		}
		if got, want := s2aAuthInfo.IsHandshakeResumed(), false; got != want {
			t.Errorf("s2aAuthInfo.IsHandshakeResumed() = %v, want %v", got, want)
		}
		if got, want := s2aAuthInfo.SecurityLevel(), credentials.PrivacyAndIntegrity; got != want {
			t.Errorf("s2aAuthInfo.SecurityLevel() = %v, want %v", got, want)
		}
	}
}

func TestV1EndToEndUsingFakeS2AOverTCP(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "")

	// Start the fake S2As for the client and server.
	serverHandshakerAddr := startFakeS2A(t, false, "")
	grpclog.Infof("Fake handshaker for server running at address: %v", serverHandshakerAddr)
	clientHandshakerAddr := startFakeS2A(t, false, "")
	grpclog.Infof("Fake handshaker for client running at address: %v", clientHandshakerAddr)

	// Start the server.
	serverAddr := startServer(t, serverHandshakerAddr, false)
	grpclog.Infof("Server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()
	runClient(ctx, t, clientHandshakerAddr, serverAddr, false)
}

func TestV2EndToEndUsingFakeS2AOverTCP(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, testV2AccessToken)

	// Start the fake S2As for the client and server.
	serverHandshakerAddr := startFakeS2A(t, true, testV2AccessToken)
	grpclog.Infof("Fake handshaker for server running at address: %v", serverHandshakerAddr)
	clientHandshakerAddr := startFakeS2A(t, true, testV2AccessToken)
	grpclog.Infof("Fake handshaker for client running at address: %v", clientHandshakerAddr)

	// Start the server.
	serverAddr := startServer(t, serverHandshakerAddr, true)
	grpclog.Infof("Server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()
	runClient(ctx, t, clientHandshakerAddr, serverAddr, true)
}
func TestV1EndToEndUsingTokens(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, testAccessToken)

	// Start the handshaker servers for the client and server.
	serverS2AAddress := startFakeS2A(t, false, "")
	grpclog.Infof("Fake S2A for server running at address: %v", serverS2AAddress)
	clientS2AAddress := startFakeS2A(t, false, "")
	grpclog.Infof("Fake S2A for client running at address: %v", clientS2AAddress)

	// Start the server.
	serverAddr := startServer(t, serverS2AAddress, false)
	grpclog.Infof("Server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddress, serverAddr, false)
}

func TestV2EndToEndUsingTokens(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, testV2AccessToken)

	// Start the handshaker servers for the client and server.
	serverS2AAddress := startFakeS2A(t, true, testV2AccessToken)
	grpclog.Infof("Fake S2A for server running at address: %v", serverS2AAddress)
	clientS2AAddress := startFakeS2A(t, true, testV2AccessToken)
	grpclog.Infof("Fake S2A for client running at address: %v", clientS2AAddress)

	// Start the server.
	serverAddr := startServer(t, serverS2AAddress, true)
	grpclog.Infof("Server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddress, serverAddr, true)
}

func TestV2EndToEndEmptyToken(t *testing.T) {
	os.Unsetenv(accessTokenEnvVariable)

	// Start the handshaker servers for the client and server.
	serverS2AAddress := startFakeS2A(t, true, testV2AccessToken)
	grpclog.Infof("Fake S2A for server running at address: %v", serverS2AAddress)
	clientS2AAddress := startFakeS2A(t, true, testV2AccessToken)
	grpclog.Infof("Fake S2A for client running at address: %v", clientS2AAddress)

	// Start the server.
	serverAddr := startServer(t, serverS2AAddress, true)
	grpclog.Infof("Server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddress, serverAddr, true)
}

func TestV1EndToEndUsingFakeS2AOnUDS(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "")

	// Start fake S2As for use by the client and server.
	serverS2AAddress := startFakeS2AOnUDS(t, false, "")
	grpclog.Infof("Fake S2A for server listening on UDS at address: %v", serverS2AAddress)
	clientS2AAddress := startFakeS2AOnUDS(t, false, "")
	grpclog.Infof("Fake S2A for client listening on UDS at address: %v", clientS2AAddress)

	// Start the server.
	serverAddress := startServer(t, serverS2AAddress, false)
	grpclog.Infof("Server running at address: %v", serverS2AAddress)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddress, serverAddress, false)
}

func TestV2EndToEndUsingFakeS2AOnUDS(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, testV2AccessToken)

	// Start fake S2As for use by the client and server.
	serverS2AAddress := startFakeS2AOnUDS(t, true, testV2AccessToken)
	grpclog.Infof("Fake S2A for server listening on UDS at address: %v", serverS2AAddress)
	clientS2AAddress := startFakeS2AOnUDS(t, true, testV2AccessToken)
	grpclog.Infof("Fake S2A for client listening on UDS at address: %v", clientS2AAddress)

	// Start the server.
	serverAddress := startServer(t, serverS2AAddress, true)
	grpclog.Infof("Server running at address: %v", serverS2AAddress)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddress, serverAddress, true)
}

func TestNewTLSClientConfigFactoryWithTokenManager(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "TestNewTLSClientConfigFactory_token")
	s2AAddr := startFakeS2A(t, true, "TestNewTLSClientConfigFactory_token")
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()

	factory, err := NewTLSClientConfigFactory(&ClientOptions{
		S2AAddress: s2AAddr,
		EnableV2:   true,
	})
	if err != nil {
		t.Errorf("NewTLSClientConfigFactory() failed: %v", err)
	}

	config, err := factory.Build(ctx, nil)
	if err != nil {
		t.Errorf("Build tls config failed: %v", err)
	}

	cert, err := tls.X509KeyPair(clientCertpem, clientKeypem)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}

	if got, want := config.Certificates[0].Certificate[0], cert.Certificate[0]; !bytes.Equal(got, want) {
		t.Errorf("tls.Config has unexpected certificate: got: %v, want: %v", got, want)
	}
}

func TestNewTLSClientConfigFactoryWithoutTokenManager(t *testing.T) {
	os.Unsetenv(accessTokenEnvVariable)
	s2AAddr := startFakeS2A(t, true, "ignored-value")
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETestTimeout)
	defer cancel()

	factory, err := NewTLSClientConfigFactory(&ClientOptions{
		S2AAddress: s2AAddr,
		EnableV2:   true,
	})
	if err != nil {
		t.Errorf("NewTLSClientConfigFactory() failed: %v", err)
	}

	config, err := factory.Build(ctx, nil)
	if err != nil {
		t.Errorf("Build tls config failed: %v", err)
	}

	cert, err := tls.X509KeyPair(clientCertpem, clientKeypem)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}
	if got, want := config.Certificates[0].Certificate[0], cert.Certificate[0]; !bytes.Equal(got, want) {
		t.Errorf("tls.Config has unexpected certificate: got: %v, want: %v", got, want)
	}
}

// startHTTPServer runs an HTTP server on a random local port and serves a /hello endpoint.
func startHTTPServer(t *testing.T) string {
	cert, _ := tls.X509KeyPair(serverCertpem, serverKeypem)
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s := http.NewServeMux()
	s.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "hello")
	})
	lis, err := tls.Listen("tcp", ":0", &tlsConfig)
	if err != nil {
		t.Errorf("net.Listen(tcp, :0) failed: %v", err)
	}
	go func() {
		http.Serve(lis, s)
	}()
	return lis.Addr().String()
}

// runHTTPClient starts an HTTP client and talks to an HTTP server using S2A.
func runHTTPClient(t *testing.T, clientS2AAddress, serverAddr string, fallbackOpts *FallbackOptions) {
	dialTLSContext := NewS2ADialTLSContextFunc(&ClientOptions{
		S2AAddress:   clientS2AAddress,
		EnableV2:     true,
		FallbackOpts: fallbackOpts,
	})

	tr := http.Transport{
		DialTLSContext: dialTLSContext,
	}

	client := &http.Client{Transport: &tr}
	reqURL := fmt.Sprintf("https://%s/hello", serverAddr)
	t.Logf("reqURL is set to: %v", reqURL)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		t.Errorf("error creating new HTTP request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("error making client HTTP request: %v", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("error reading HTTP response: %v", err)
	}
	if got, want := string(respBody), "hello"; got != want {
		t.Errorf("expecting HTTP response:[%s], got [%s]", want, got)
	}
}
func TestHTTPEndToEndUsingFakeS2AOverTCP(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, testV2AccessToken)

	// Start the fake S2As for the client.
	clientHandshakerAddr := startFakeS2A(t, true, testV2AccessToken)
	t.Logf("fake handshaker for client running at address: %v", clientHandshakerAddr)

	// Start the server.
	serverAddr := startHTTPServer(t)
	t.Logf("HTTP server running at address: %v", serverAddr)

	// Finally, start up the client.
	runHTTPClient(t, clientHandshakerAddr, serverAddr, nil)
}

func TestHTTPFallbackEndToEndUsingFakeS2AOverTCP(t *testing.T) {
	fallback.FallbackTLSConfigHTTP = tls.Config{
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: nil,
		NextProtos:         []string{"http/1.1", "h2"},
		// set for testing only
		InsecureSkipVerify: true,
	}
	os.Setenv(accessTokenEnvVariable, testV2AccessToken)

	// Start the server.
	serverAddr := startHTTPServer(t)
	t.Logf("HTTP server running at address: %v", serverAddr)

	fallbackServerAddr := startHTTPServer(t)
	t.Logf("fallback HTTP server running at address: %v", fallbackServerAddr)

	// Configure fallback options.
	fbDialer, fbAddr, err := fallback.DefaultFallbackDialerAndAddress(fallbackServerAddr)
	if err != nil {
		t.Errorf("error creating fallback dialer: %v", err)
	}
	fallbackOpts := &FallbackOptions{
		FallbackDialer: &FallbackDialer{
			Dialer:     fbDialer,
			ServerAddr: fbAddr,
		},
	}
	// Set wrong client S2A address to trigger S2A failure and fallback.
	runHTTPClient(t, "not_exist", serverAddr, fallbackOpts)
}
