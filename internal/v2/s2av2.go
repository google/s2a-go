// Package v2 provides the S2Av2 transport credentials used by a gRPC
// application.
package v2

import (
	"errors"
	"context"
	"net"
	"time"
	"flag"
	"log"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/google/s2a-go/internal/v2/tls_config_store"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

const (
	s2aSecurityProtocol = "s2av2"
	defaultTimeout = 10.0 * time.Second
)

var (
	fakes2av2Address = flag.String("address", "0.0.0.0:8008", "Fake S2Av2 address")
)

type s2av2TransportCreds struct {
	info     *credentials.ProtocolInfo
	isClient bool
	serverName string
}

// NewClientCreds returns a client-side transport credentials object that uses
// the S2Av2 to establish a secure connection with a server.
func NewClientCreds() (credentials.TransportCredentials, error) {
	creds := &s2av2TransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		isClient: true,
		serverName: "",
	}
	return creds, nil
}

// NewServerCreds returns a server-side transport credentials object that uses
// the S2Av2 to establish a secure connection with a client.
func NewServerCreds() (credentials.TransportCredentials, error) {
	creds := &s2av2TransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		isClient: false,
	}
	return creds, nil
}

// ClientHandshake performs a client-side mTLS handshake using the S2Av2.
func (c *s2av2TransportCreds) ClientHandshake(ctx context.Context, serverAuthority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !c.isClient {
		return nil, nil, errors.New("client handshake called using server transport credentials")
	}
	// Remove the port from serverAuthority.
	serverName, _, err := net.SplitHostPort(serverAuthority)
	if err != nil {
		serverName = serverAuthority
	}
	// Create a stream to S2Av2.
	opts := []grpc.DialOption {
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithReturnConnectionError(),
		grpc.WithBlock(),
	}
	conn, err := grpc.Dial(*fakes2av2Address, opts...)
	if err != nil {
		log.Fatalf("Client: failed to connect: %v", err)
	}
	defer conn.Close()
	client := s2av2pb.NewS2AServiceClient(conn)
	log.Printf("Client: connected to: %s", *fakes2av2Address)
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Setup bidrectional streaming session.
	callOpts := []grpc.CallOption{}
	cstream, err := client.SetUpSession(ctx, callOpts...)
	if err != nil  {
		log.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
	}
	log.Printf("Client: set up bidirectional streaming RPC session.")

	var config *tls.Config
	if c.serverName == "" {
		config = tlsconfigstore.GetTlsConfigurationForClient(serverName, cstream)
	} else {
		config = tlsconfigstore.GetTlsConfigurationForClient(c.serverName, cstream)
	}
	creds := credentials.NewTLS(config)
	return creds.ClientHandshake(context.Background(), serverName, rawConn)
}

// ServerHandshake performs a server-side mTLS handshake using the S2Av2.
func (c *s2av2TransportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.isClient {
		return nil, nil, errors.New("server handshake called using client transport credentials")
	}

	// Create a stream to S2Av2.
	opts := []grpc.DialOption {
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithReturnConnectionError(),
		grpc.WithBlock(),
	}
	conn, err := grpc.Dial(*fakes2av2Address, opts...)
	if err != nil {
		log.Fatalf("Client: failed to connect: %v", err)
	}
	defer conn.Close()
	client := s2av2pb.NewS2AServiceClient(conn)
	log.Printf("Client: connected to: %s", *fakes2av2Address)
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Setup bidrectional streaming session.
	callOpts := []grpc.CallOption{}
	cstream, err := client.SetUpSession(ctx, callOpts...)
	if err != nil  {
		log.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
	}
	log.Printf("Client: set up bidirectional streaming RPC session.")

	config := tlsconfigstore.GetTlsConfigurationForServer(cstream)
	creds := credentials.NewTLS(config)
	return creds.ServerHandshake(rawConn)
}

// Info returns protocol info of s2av2TransportCreds.
func (c *s2av2TransportCreds) Info() credentials.ProtocolInfo {
	return *c.info
}

// Clone makes a deep copy of s2av2TransportCreds.
func (c * s2av2TransportCreds) Clone() credentials.TransportCredentials {
	info := *c.info
	serverName := c.serverName
	return &s2av2TransportCreds{
		info: &info,
		isClient: c.isClient,
		serverName: serverName,
	}
}

// OverrideServerName sets the ServerName in the s2av2TransportCreds protocol
// info. The ServerName MUST be a hostname.
func (c *s2av2TransportCreds) OverrideServerName(serverNameOverride string) error{
	// Remove the port from serverNameOverride.
	serverName, _, err := net.SplitHostPort(serverNameOverride)
	if err != nil {
		serverName = serverNameOverride
	}
	c.info.ServerName = serverName
	c.serverName = serverName
	return nil
}
