/*
 *
 * Copyright 2023 Google LLC
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

// Package fallback provides default implementations of fallback options when S2A fails.
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
	alpnProtoStrHttp = "http/1.1"
	defaultHttpsPort = "443"
)

// FallbackClientHandshake establishes a TLS connection and returns it, plus its auth info.
// Input:
//
//	targetServer: the server attempted with S2A.
//	conn: the raw tcp connection passed into S2A's ClientHandshake func.
//	            If fallback is successful, the `conn` should be closed.
//	err: the error encountered when performing client handshake with S2A.
type FallbackClientHandshake func(ctx context.Context, targetServer string, conn net.Conn, err error) (net.Conn, credentials.AuthInfo, error)

// DefaultFallbackClientHandshakeFunc returns an implementation of FallbackOptions.FallbackClientHandshakeFunc,
// which is of type FallbackClientHandshake.
// It establishes a TLS connection with the provided fallbackAddr, returns the new connection and its auth info.
// Example use:
//
//	transportCreds, _ = s2a.NewClientCreds(&s2a.ClientOptions{
//		S2AAddress: s2aAddress,
//		EnableV2:   true,
//		FallbackOpts: &s2a.FallbackOptions{ // optional
//			FallbackClientHandshakeFunc: fallback.DefaultFallbackClientHandshakeFunc(fallbackAddr),
//		},
//	})
//
// The fallback server's certificate should be verifiable using OS root store.
// The fallbackAddr is expected to be a network address, e.g. example.com:port. If port is not specified,
// it uses default port 443.
// In the returned function's TLS config, ClientSessionCache is explicitly set to nil to disable TLS resumption,
// and min TLS version is set to 1.3.
func DefaultFallbackClientHandshakeFunc(fallbackAddr string) (func(context.Context, string, net.Conn, error) (net.Conn, credentials.AuthInfo, error), error) {
	fallbackServerAddr, err := processFallbackAddr(fallbackAddr)
	if err != nil {
		if grpclog.V(1) {
			grpclog.Infof("error processing fallback address [%s]: %v", fallbackAddr, err)
		}
		return nil, err
	}
	return func(ctx context.Context, targetServer string, conn net.Conn, s2aErr error) (net.Conn, credentials.AuthInfo, error) {
		fallbackTLSConfig := tls.Config{
			MinVersion:         tls.VersionTLS13,
			ClientSessionCache: nil,
			NextProtos:         []string{alpnProtoStrH2},
		}
		fallbackDialer := &tls.Dialer{Config: &fallbackTLSConfig}
		fbConn, fbErr := fallbackDialer.DialContext(ctx, "tcp", fallbackServerAddr)
		if fbErr != nil {
			grpclog.Infof("dialing to fallback server %s failed: %v", fallbackServerAddr, fbErr)
			return nil, nil, fmt.Errorf("dialing to fallback server %s failed: %v; S2A client handshake with %s error: %w", fallbackServerAddr, fbErr, targetServer, s2aErr)
		}

		tc, success := fbConn.(*tls.Conn)
		if !success {
			grpclog.Infof("the connection with fallback server is expected to be tls but isn't")
			return nil, nil, fmt.Errorf("the connection with fallback server is expected to be tls but isn't; S2A client handshake with %s error: %w", targetServer, s2aErr)
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
		conn.Close()
		return fbConn, tlsInfo, nil
	}, nil
}

// DefaultFallbackDialerAndAddress returns a TLS dialer and a network address for it to dial with.
// Example use:
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
// The fallback server's certificate should be verifiable using OS root store.
// The fallbackAddr is expected to be a network address, e.g. example.com:port. If port is not specified,
// it uses default port 443.
// In the returned function's TLS config, ClientSessionCache is explicitly set to nil to disable TLS resumption,
// and min TLS version is set to 1.3.
func DefaultFallbackDialerAndAddress(fallbackAddr string) (*tls.Dialer, string, error) {
	fallbackServerAddr, err := processFallbackAddr(fallbackAddr)
	if err != nil {
		if grpclog.V(1) {
			grpclog.Infof("error processing fallback address [%s]: %v", fallbackAddr, err)
		}
		return nil, "", err
	}
	fallbackTLSConfig := tls.Config{
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: nil,
		NextProtos:         []string{alpnProtoStrHttp},
	}
	return &tls.Dialer{Config: &fallbackTLSConfig}, fallbackServerAddr, nil
}

func processFallbackAddr(fallbackAddr string) (string, error) {
	var fallbackServerAddr string
	var err error

	if fallbackAddr == "" {
		return "", fmt.Errorf("empty fallback address")
	}
	_, _, err = net.SplitHostPort(fallbackAddr)
	if err != nil {
		// fallbackAddr does not have port suffix
		fallbackServerAddr = net.JoinHostPort(fallbackAddr, defaultHttpsPort)
	} else {
		// FallbackServerAddr already has port suffix
		fallbackServerAddr = fallbackAddr
	}
	return fallbackServerAddr, nil
}
