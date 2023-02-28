package fallback

import (
	"context"
	"crypto/tls"
	"fmt"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"net"
)

const (
	alpnProtoStrH2   = "h2"
	defaultHttpsPort = "443"
)

// DefaultFallbackClientHandshakeFunc returns an implementation of FallbackOptions.FallbackClientHandshakeFunc.
// example use:
//
//	transportCreds, _ = s2a.NewClientCreds(&s2a.ClientOptions{
//		S2AAddress: s2aAddress,
//		EnableV2:   true,
//		FallbackOpts: &s2a.FallbackOptions{ // optional, and for V2 only
//			FallbackClientHandshakeFunc: fallback.DefaultFallbackClientHandshakeFunc(fallbackAddr),
//		},
//	})
//
// The fallbackAddr is expected to be a network address, e.g. example.com:port. If port is not specified,
// it uses default port 443
func DefaultFallbackClientHandshakeFunc(fallbackAddr string) func(ctx context.Context, originConn net.Conn, originErr error) (net.Conn, credentials.AuthInfo, error) {
	return func(ctx context.Context, originConn net.Conn, originErr error) (net.Conn, credentials.AuthInfo, error) {
		fallbackServerAddr, fallbackServerName, err := processFallbackAddr(fallbackAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("no fallback server address specified, skipping fallback; S2Av2 client handshake error: %w", originErr)
		}

		fallbackTLSConfig := tls.Config{
			ServerName: fallbackServerName,
			NextProtos: []string{alpnProtoStrH2},
		}
		fallbackDialer := &tls.Dialer{Config: &fallbackTLSConfig}
		fbConn, fbErr := fallbackDialer.DialContext(ctx, "tcp", fallbackServerAddr)
		if fbErr != nil {
			grpclog.Infof("dialing to fallback server %s failed: %v", fallbackServerAddr, fbErr)
			return nil, nil, fmt.Errorf("dialing to fallback server %s failed: %v; S2Av2 client handshake error: %w", fallbackServerAddr, fbErr, originErr)
		}

		tc, success := fbConn.(*tls.Conn)
		if !success {
			grpclog.Infof("the connection with fallback server is expected to be tls but isn't")
			return nil, nil, fmt.Errorf("the connection with fallback server is expected to be tls but isn't; S2Av2 client handshake error: %w", originErr)
		}

		tlsInfo := credentials.TLSInfo{
			State: tc.ConnectionState(),
			CommonAuthInfo: credentials.CommonAuthInfo{
				SecurityLevel: credentials.PrivacyAndIntegrity,
			},
		}
		if grpclog.V(1) {
			grpclog.Infof("ConnectionState.NegotiatedProtocol: %v", tc.ConnectionState().NegotiatedProtocol)
			grpclog.Infof("ConnectionState.HandshakeComplete: %v", tc.ConnectionState().HandshakeComplete)
			grpclog.Infof("ConnectionState.ServerName: %v", tc.ConnectionState().ServerName)
		}
		originConn.Close()
		return fbConn, tlsInfo, nil
	}
}

// DefaultFallbackDialerAndAddress returns a TLS dialer and a network address for it to dial with.
// example use:
//
//	    fallbackDialer, fallbackServerAddr := fallback.DefaultFallbackDialerAndAddress(fallbackAddr)
//		dialTLSContext := s2a.NewS2aDialTLSContextFunc(&s2a.ClientOptions{
//			S2AAddress:         s2aAddress, // required
//			EnableV2:           true, // must be true
//			FallbackOpts: &s2a.FallbackOptions{
//				FallbackDialer: &s2a.FallbackDialer{
//					Dialer:     fallbackDialer,
//					ServerAddr: fallbackServerAddr,
//				},
//			},
//	})
//
// The fallbackAddr is expected to be a network address, e.g. example.com:port. If port is not specified,
// it uses default port 443
func DefaultFallbackDialerAndAddress(fallbackAddr string) (*tls.Dialer, string) {
	var fallbackDialer *tls.Dialer
	fallbackServerAddr, fallbackServerName, err := processFallbackAddr(fallbackAddr)
	if err == nil {
		fallbackTLSConfig := tls.Config{
			ServerName: fallbackServerName,
		}
		fallbackDialer = &tls.Dialer{Config: &fallbackTLSConfig}

		return fallbackDialer, fallbackServerAddr
	}
	return nil, ""
}

func processFallbackAddr(fallbackAddr string) (string, string, error) {
	// hostname:port
	var fallbackServerAddr string
	// hostname
	var fallbackServerName string
	var err error

	if fallbackAddr != "" {
		fallbackServerName, _, err = net.SplitHostPort(fallbackAddr)
		if err != nil {
			// fallbackAddr does not have port suffix
			fallbackServerAddr = net.JoinHostPort(fallbackAddr, defaultHttpsPort)
			fallbackServerName = fallbackAddr
		} else {
			// FallbackServerAddr already has port suffix
			fallbackServerAddr = fallbackAddr
		}
		return fallbackServerAddr, fallbackServerName, nil
	}
	return "", "", fmt.Errorf("empty fallback address")
}
