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
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	commonpb "github.com/s2a-go/internal/proto/common_go_proto"
	grpcpb "github.com/s2a-go/internal/proto/s2a_go_grpc_proto"
	"google.golang.org/grpc/credentials"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/peer"
	"github.com/s2a-go/internal/fakehandshaker/service"
	helloworldgrpcpb "github.com/s2a-go/internal/proto/examples/helloworld_go_grpc_proto"
	
)

const (
	accessTokenEnvVariable = "S2A_ACCESS_TOKEN"
	testAccessToken        = "test_access_token"

	applicationProtocol = "grpc"
	authType            = "s2a"
	clientHostname      = "test_client_hostname"
	serverSpiffeID      = "test_server_spiffe_id"
	clientMessage       = "echo"
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	helloworldgrpcpb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer.
func (s *server) SayHello(_ context.Context, in *helloworldgrpcpb.HelloRequest) (*helloworldgrpcpb.HelloReply, error) {
	return &helloworldgrpcpb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

// startFakeS2A starts up a fake S2A and returns the address that it is listening on.
func startFakeS2A(t *testing.T) string {
	lis, err := net.Listen("tcp", ":")
	if err != nil {
		t.Errorf("net.Listen(tcp, :0) failed: %v", err)
	}
	s := grpc.NewServer()
	grpcpb.RegisterS2AServiceServer(s, &service.FakeHandshakerService{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

func startFakeS2AOnUDS(t *testing.T) string {
	dir, err := ioutil.TempDir("/tmp", "socket_dir")
	if err != nil {
		t.Errorf("unable to create temporary directory: %v", err)
	}
	udsAddress := filepath.Join(dir, "socket")
	lis, err := net.Listen("unix", filepath.Join(dir, "socket"))
	if err != nil {
		t.Errorf("net.Listen(unix, %s) failed: %v", udsAddress, err)
	}
	s := grpc.NewServer()
	grpcpb.RegisterS2AServiceServer(s, &service.FakeHandshakerService{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return fmt.Sprintf("unix://%s", lis.Addr().String())
}

// startServer starts up a server and returns the address that it is listening
// on.
func startServer(t *testing.T, s2aAddress string) string {
	serverOpts := &ServerOptions{
		LocalIdentities: []Identity{NewSpiffeID(serverSpiffeID)},
		S2AAddress:      s2aAddress,
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
	helloworldgrpcpb.RegisterGreeterServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

// runClient starts up a client and calls the server.
func runClient(ctx context.Context, t *testing.T, clientS2AAddress, serverAddr string) {
	clientOpts := &ClientOptions{
		TargetIdentities: []Identity{NewSpiffeID(serverSpiffeID)},
		LocalIdentity:    NewHostname(clientHostname),
		S2AAddress:       clientS2AAddress,
	}
	creds, err := NewClientCreds(clientOpts)
	if err != nil {
		t.Errorf("NewClientCreds(%v) failed: %v", clientOpts, err)
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	}

	grpclog.Info("client dialing server at address: %v", serverAddr)
	// Establish a connection to the server.
	conn, err := grpc.Dial(serverAddr, dialOptions...)
	if err != nil {
		t.Errorf("grpc.Dial(%v, %v) failed: %v", serverAddr, dialOptions, err)
	}
	defer conn.Close()

	// Contact the server.
	peer := new(peer.Peer)
	c := helloworldgrpcpb.NewGreeterClient(conn)
	req := &helloworldgrpcpb.HelloRequest{Name: clientMessage}
	grpclog.Infof("client calling SayHello with request: %v", req)
	resp, err := c.SayHello(ctx, req, grpc.Peer(peer), grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("c.SayHello(%v, %v) failed: %v", ctx, req, err)
	}
	if got, want := resp.GetMessage(), "Hello "+clientMessage; got != want {
		t.Errorf("r.GetMessage() = %v, want %v", got, want)
	}

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

func TestEndToEndUsingFakeS2AOverTCP(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "")

	// Start the fake S2As for the client and server.
	serverHandshakerAddr := startFakeS2A(t)
	grpclog.Infof("fake handshaker for server running at address: %v", serverHandshakerAddr)
	clientHandshakerAddr := startFakeS2A(t)
	grpclog.Infof("fake handshaker for client running at address: %v", clientHandshakerAddr)

	// Start the server.
	serverAddr := startServer(t, serverHandshakerAddr)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	runClient(ctx, t, clientHandshakerAddr, serverAddr)
}

func TestEndToEndUsingTokens(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, testAccessToken)

	// Start the handshaker servers for the client and server.
	serverS2AAddress := startFakeS2A(t)
	grpclog.Infof("fake S2A for server running at address: %v", serverS2AAddress)
	clientS2AAddress := startFakeS2A(t)
	grpclog.Infof("fake S2A for client running at address: %v", clientS2AAddress)

	// Start the server.
	serverAddr := startServer(t, serverS2AAddress)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	runClient(ctx, t, clientS2AAddress, serverAddr)
}

func TestEndToEndUsingFakeS2AOnUDS(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "")

	// Start fake S2As for use by the client and server.
	serverS2AAddress := startFakeS2AOnUDS(t)
	grpclog.Infof("fake S2A for server listening on UDS at address: %v", serverS2AAddress)
	clientS2AAddress := startFakeS2AOnUDS(t)
	grpclog.Infof("fake S2A for client listening on UDS at address: %v", clientS2AAddress)

	// Start the server.
	serverAddress := startServer(t, serverS2AAddress)
	grpclog.Infof("server running at address: %v", serverS2AAddress)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	runClient(ctx, t, clientS2AAddress, serverAddress)
}
