package v2

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
	helloworldpb "github.com/google/s2a-go/internal/proto/examples/helloworld_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

const (
	accessTokenEnvVariable = "S2A_ACCESS_TOKEN"
	defaultE2ETimeout      = time.Second * 5
	clientMessage          = "echo"
)

// server implements the helloworld.GreeterServer.
type server struct {
	helloworldpb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer.
func (s *server) SayHello(_ context.Context, in *helloworldpb.HelloRequest) (*helloworldpb.HelloReply, error) {
	return &helloworldpb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

// startFakeS2A starts up a fake S2A and returns the address that it is
// listening on.
func startFakeS2A(t *testing.T, expToken string) string {
	lis, err := net.Listen("tcp", ":")
	if err != nil {
		t.Errorf("net.Listen(tcp, :0) failed: %v", err)
	}
	s := grpc.NewServer()
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{ExpectedToken: expToken})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

// startFakeS2A starts up a fake S2A on UDS and returns the address that it is
// listening on.
func startFakeS2AOnUDS(t *testing.T, expToken string) string {
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
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{ExpectedToken: expToken})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return fmt.Sprintf("unix://%s", lis.Addr().String())
}

// startServer starts up a server and returns the address that it is listening
// on.
func startServer(t *testing.T, s2aAddress string, localIdentities []*commonpbv1.Identity) string {
	creds, err := NewServerCreds(s2aAddress, localIdentities)
	if err != nil {
		t.Errorf("NewServerCreds(%s) failed: %v", s2aAddress, err)
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
func runClient(ctx context.Context, t *testing.T, clientS2AAddress, serverAddr string, localIdentity *commonpbv1.Identity) {
	creds, err := NewClientCreds(clientS2AAddress, localIdentity)
	if err != nil {
		t.Errorf("NewClientCreds(%s) failed: %v", clientS2AAddress, err)
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
	c := helloworldpb.NewGreeterClient(conn)
	req := &helloworldpb.HelloRequest{Name: clientMessage}
	grpclog.Infof("client calling SayHello with request: %v", req)
	resp, err := c.SayHello(ctx, req, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("c.SayHello(%v, %v) failed: %v", ctx, req, err)
	}
	if got, want := resp.GetMessage(), "Hello "+clientMessage; got != want {
		t.Errorf("r.GetMessage() = %v, want %v", got, want)
	}
	grpclog.Infof("client received message from server: %s", resp.GetMessage())
}

func TestEndToEndUsingFakeS2AOverTCP(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "TestE2ETCP_token")
	// Start the fake S2As for the client and server.
	serverS2AAddr := startFakeS2A(t, "TestE2ETCP_token")
	grpclog.Infof("fake handshaker for server running at address: %v", serverS2AAddr)
	clientS2AAddr := startFakeS2A(t, "TestE2ETCP_token")
	grpclog.Infof("fake handshaker for client running at address: %v", clientS2AAddr)

	// Start the server.
	var localIdentities []*commonpbv1.Identity
	localIdentities = append(localIdentities, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_server_identity",
		},
	})
	serverAddr := startServer(t, serverS2AAddr, localIdentities)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddr, serverAddr, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	})
}

func TestEndToEndUsingFakeS2AOverTCPEmptyId(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "TestE2ETCP_token")
	// Start the fake S2As for the client and server.
	serverS2AAddr := startFakeS2A(t, "TestE2ETCP_token")
	grpclog.Infof("fake handshaker for server running at address: %v", serverS2AAddr)
	clientS2AAddr := startFakeS2A(t, "TestE2ETCP_token")
	grpclog.Infof("fake handshaker for client running at address: %v", clientS2AAddr)

	// Start the server.
	var localIdentities []*commonpbv1.Identity
	localIdentities = append(localIdentities, nil)
	serverAddr := startServer(t, serverS2AAddr, localIdentities)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddr, serverAddr, nil)
}

func TestEndToEndUsingFakeS2AOnUDS(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "TestE2EUDS_token")
	// Start fake S2As for use by the client and server.
	serverS2AAddr := startFakeS2AOnUDS(t, "TestE2EUDS_token")
	grpclog.Infof("fake S2A for server listening on UDS at address: %v", serverS2AAddr)
	clientS2AAddr := startFakeS2AOnUDS(t, "TestE2EUDS_token")
	grpclog.Infof("fake S2A for client listening on UDS at address: %v", clientS2AAddr)

	// Start the server.
	var localIdentities []*commonpbv1.Identity
	localIdentities = append(localIdentities, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_server_identity",
		},
	})
	serverAddr := startServer(t, serverS2AAddr, localIdentities)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddr, serverAddr, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	})
}

func TestEndToEndUsingFakeS2AOnUDSEmptyId(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "TestE2EUDS_token")
	// Start fake S2As for use by the client and server.
	serverS2AAddr := startFakeS2AOnUDS(t, "TestE2EUDS_token")
	grpclog.Infof("fake S2A for server listening on UDS at address: %v", serverS2AAddr)
	clientS2AAddr := startFakeS2AOnUDS(t, "TestE2EUDS_token")
	grpclog.Infof("fake S2A for client listening on UDS at address: %v", clientS2AAddr)

	// Start the server.
	var localIdentities []*commonpbv1.Identity
	localIdentities = append(localIdentities, nil)
	serverAddr := startServer(t, serverS2AAddr, localIdentities)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddr, serverAddr, nil)
}
