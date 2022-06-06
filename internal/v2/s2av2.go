// Package v2 provides the S2Av2 transport credentials used by a gRPC
// application.
package v2

import (
	"errors"
	"context"
	"net"
	"crypto/tls"

	"google.golang.org/grpc/credentials"
	"github.com/google/s2a-go/internal/v2/tls_config_store"
)

const (
	s2aSecurityProtocol = "s2av2"
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
	// TODO(rmehta19): Create a stub to S2Av2.
	var config *tls.Config
	if c.serverName == "" {
		config = tlsconfigstore.GetTlsConfigurationForClient(serverName)
	} else {
		config = tlsconfigstore.GetTlsConfigurationForClient(c.serverName)
	}
	creds := credentials.NewTLS(config)
	return creds.ClientHandshake(context.Background(), serverName, rawConn)
}

// ServerHandshake performs a server-side mTLS handshake using the S2Av2.
func (c *s2av2TransportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.isClient {
		return nil, nil, errors.New("server handshake called using client transport credentials")
	}
	// TODO(rmehta19): Create a stub to S2Av2.
	config := tlsconfigstore.GetTlsConfigurationForServer()
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
