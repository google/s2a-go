// Package v2 provides the S2Av2 transport credentials used by a gRPC
// application.
package v2

import (
	"errors"
	"context"
	"net"
	"time"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/google/s2a-go/internal/v2/tls_config_store"
	"github.com/google/s2a-go/internal/tokenmanager"
	"github.com/google/s2a-go/internal/handshaker/service"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
)

const (
	s2aSecurityProtocol = "s2av2"
	defaultTimeout = 20.0 * time.Second
)

type s2av2TransportCreds struct {
	info     *credentials.ProtocolInfo
	isClient bool
	serverName string
	s2av2Address string
	tokenManager *tokenmanager.AccessTokenManager
}

// NewClientCreds returns a client-side transport credentials object that uses
// the S2Av2 to establish a secure connection with a server.
func NewClientCreds(s2av2Address string) (credentials.TransportCredentials, error) {
	// Create an AccessTokenManager instance to use to authenticate to S2Av2.
	accessTokenManager, err := tokenmanager.NewSingleTokenAccessTokenManager()
	if err != nil {
		return nil, err
	}
	creds := &s2av2TransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		isClient: true,
		serverName: "",
		s2av2Address: s2av2Address,
		tokenManager: &accessTokenManager,
	}
	return creds, nil
}

// NewServerCreds returns a server-side transport credentials object that uses
// the S2Av2 to establish a secure connection with a client.
func NewServerCreds(s2av2Address string) (credentials.TransportCredentials, error) {
	// Create an AccessTokenManager instance to use to authenticate to S2Av2.
	accessTokenManager, err := tokenmanager.NewSingleTokenAccessTokenManager()
	if err != nil {
		return nil, err
	}
	creds := &s2av2TransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		isClient: false,
		s2av2Address: s2av2Address,
		tokenManager: &accessTokenManager,
	}
	return creds, nil
}

// ClientHandshake performs a client-side mTLS handshake using the S2Av2.
func (c *s2av2TransportCreds) ClientHandshake(ctx context.Context, serverAuthority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !c.isClient {
		return nil, nil, errors.New("client handshake called using server transport credentials.")
	}
	// Remove the port from serverAuthority.
	serverName, _, err := net.SplitHostPort(serverAuthority)
	if err != nil {
		serverName = serverAuthority
	}
	cstream, err := c.createStream()
	if err != nil {
		return nil, nil, err
	}
	var config *tls.Config

	// TODO(rmehta19): Populate localIdentity.
	var localIdentity commonpbv1.Identity
	if c.serverName == "" {
		config, err = tlsconfigstore.GetTlsConfigurationForClient(serverName, cstream, *c.tokenManager, &localIdentity)
		if err != nil {
			return nil, nil, err
		}
	} else {
		config, err = tlsconfigstore.GetTlsConfigurationForClient(c.serverName, cstream, *c.tokenManager, &localIdentity)
		if err != nil {
			return nil, nil, err
		}
	}
	creds := credentials.NewTLS(config)

	return creds.ClientHandshake(context.Background(), serverName, rawConn)
}

// ServerHandshake performs a server-side mTLS handshake using the S2Av2.
func (c *s2av2TransportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.isClient {
		return nil, nil, errors.New("server handshake called using client transport credentials.")
	}
	cstream, err := c.createStream()
	if err != nil {
		return nil, nil, err
	}

	// TODO(rmehta19): Populate localIdentites.
	var localIdentities [] *commonpbv1.Identity
	localIdentities = append(localIdentities, nil)
	config, err := tlsconfigstore.GetTlsConfigurationForServer(cstream, *c.tokenManager, localIdentities)
	if err != nil {
		return nil, nil, err
	}
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
	s2av2Address := c.s2av2Address
	tokenManager := *c.tokenManager
	return &s2av2TransportCreds{
		info: &info,
		isClient: c.isClient,
		serverName: serverName,
		s2av2Address : s2av2Address,
		tokenManager: &tokenManager,
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

func (c* s2av2TransportCreds) createStream() (s2av2pb.S2AService_SetUpSessionClient, error) {
	// TODO(rmehta19): Consider whether to close the connection to S2Av2.
	conn, err := service.Dial(c.s2av2Address)
	if err != nil {
		return nil, err
	}
	client := s2av2pb.NewS2AServiceClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	// TODO(rmehta19): Consider canceling the context(defer cancel()) when it
	// times out.
	return client.SetUpSession(ctx, []grpc.CallOption{}...)
}
