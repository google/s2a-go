package v2

import (
	"os"
	"time"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"testing"

	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	helloworldpb "github.com/google/s2a-go/internal/proto/examples/helloworld_go_proto"
)

const (
	accessTokenEnvVariable = "S2A_ACCESS_TOKEN"
	testAccessToken        = "test_access_token"
	defaultE2ETimeout      = time.Second*5
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
func startFakeS2A(t *testing.T) string {
	lis, err := net.Listen("tcp", ":")
	if err != nil {
		t.Errorf("net.Listen(tcp, :0) failed: %v", err)
	}
	s := grpc.NewServer()
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

// startFakeS2A starts up a fake S2A on UDS and returns the address that it is
// listening on.
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
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{})
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
	creds, err := NewServerCreds(s2aAddress)
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
func runClient(ctx context.Context, t *testing.T, clientS2AAddress, serverAddr string) {
	creds, err := NewClientCreds(clientS2AAddress)
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
	os.Setenv(accessTokenEnvVariable, testAccessToken)
	// Start the fake S2As for the client and server.
	serverS2AAddr := startFakeS2A(t)
	grpclog.Infof("fake handshaker for server running at address: %v", serverS2AAddr)
	clientS2AAddr := startFakeS2A(t)
	grpclog.Infof("fake handshaker for client running at address: %v", clientS2AAddr)

	// Start the server.
	serverAddr := startServer(t, serverS2AAddr)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddr, serverAddr)
}

func TestEndToEndUsingFakeS2AOnUDS(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, testAccessToken)
	// Start fake S2As for use by the client and server.
	serverS2AAddr := startFakeS2AOnUDS(t)
	grpclog.Infof("fake S2A for server listening on UDS at address: %v", serverS2AAddr)
	clientS2AAddr := startFakeS2AOnUDS(t)
	grpclog.Infof("fake S2A for client listening on UDS at address: %v", clientS2AAddr)

	// Start the server.
	serverAddr := startServer(t, serverS2AAddr)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), defaultE2ETimeout)
	defer cancel()
	runClient(ctx, t, clientS2AAddr, serverAddr)
}
