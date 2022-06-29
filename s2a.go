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

// Package s2a provides the S2A transport credentials used by a gRPC
// application.
package s2a

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"github.com/golang/protobuf/proto"
	"github.com/google/s2a-go/internal/handshaker"
	"github.com/google/s2a-go/internal/handshaker/service"
	"github.com/google/s2a-go/internal/v2"
	commonpb "github.com/google/s2a-go/internal/proto/common_go_proto"
)

const (
	s2aSecurityProtocol = "s2a"
	// defaultTimeout specifies the default server handshake timeout.
	defaultTimeout = 30.0 * time.Second
)

// s2aTransportCreds are the transport credentials required for establishing
// a secure connection using the S2A. They implement the
// credentials.TransportCredentials interface.
type s2aTransportCreds struct {
	info          *credentials.ProtocolInfo
	minTLSVersion commonpb.TLSVersion
	maxTLSVersion commonpb.TLSVersion
	// tlsCiphersuites contains the ciphersuites used in the S2A connection.
	// Note that these are currently unconfigurable.
	tlsCiphersuites []commonpb.Ciphersuite
	// localIdentity should only be used by the client.
	localIdentity *commonpb.Identity
	// localIdentities should only be used by the server.
	localIdentities []*commonpb.Identity
	// targetIdentities should only be used by the client.
	targetIdentities            []*commonpb.Identity
	isClient                    bool
	s2aAddr                     string
	ensureProcessSessionTickets *sync.WaitGroup
}

// NewClientCreds returns a client-side transport credentials object that uses
// the S2A to establish a secure connection with a server.
func NewClientCreds(opts *ClientOptions) (credentials.TransportCredentials, error) {
	if opts == nil {
		return nil, errors.New("nil client options")
	}
	var targetIdentities []*commonpb.Identity
	for _, targetIdentity := range opts.TargetIdentities {
		protoTargetIdentity, err := toProtoIdentity(targetIdentity)
		if err != nil {
			return nil, err
		}
		targetIdentities = append(targetIdentities, protoTargetIdentity)
	}
	localIdentity, err := toProtoIdentity(opts.LocalIdentity)
	if err != nil {
		return nil, err
	}
	if opts.EnableV2 {
		return v2.NewClientCreds(opts.S2AAddress)
	} else {
		return &s2aTransportCreds{
			info: &credentials.ProtocolInfo{
				SecurityProtocol: s2aSecurityProtocol,
			},
			minTLSVersion: commonpb.TLSVersion_TLS1_3,
			maxTLSVersion: commonpb.TLSVersion_TLS1_3,
			tlsCiphersuites: []commonpb.Ciphersuite{
				commonpb.Ciphersuite_AES_128_GCM_SHA256,
				commonpb.Ciphersuite_AES_256_GCM_SHA384,
				commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			},
			localIdentity:               localIdentity,
			targetIdentities:            targetIdentities,
			isClient:                    true,
			s2aAddr:                     opts.S2AAddress,
			ensureProcessSessionTickets: opts.EnsureProcessSessionTickets,
		}, nil
	}
}

// NewServerCreds returns a server-side transport credentials object that uses
// the S2A to establish a secure connection with a client.
func NewServerCreds(opts *ServerOptions) (credentials.TransportCredentials, error) {
	if opts == nil {
		return nil, errors.New("nil server options")
	}
	var localIdentities []*commonpb.Identity
	for _, localIdentity := range opts.LocalIdentities {
		protoLocalIdentity, err := toProtoIdentity(localIdentity)
		if err != nil {
			return nil, err
		}
		localIdentities = append(localIdentities, protoLocalIdentity)
	}
	if opts.EnableV2 {
		return v2.NewServerCreds(opts.S2AAddress)
	} else {
		return &s2aTransportCreds{
			info: &credentials.ProtocolInfo{
				SecurityProtocol: s2aSecurityProtocol,
			},
			minTLSVersion: commonpb.TLSVersion_TLS1_3,
			maxTLSVersion: commonpb.TLSVersion_TLS1_3,
			tlsCiphersuites: []commonpb.Ciphersuite{
				commonpb.Ciphersuite_AES_128_GCM_SHA256,
				commonpb.Ciphersuite_AES_256_GCM_SHA384,
				commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			},
			localIdentities: localIdentities,
			isClient:        false,
			s2aAddr:         opts.S2AAddress,
		}, nil
	}
}

// ClientHandshake initiates a client-side TLS handshake using the S2A.
func (c *s2aTransportCreds) ClientHandshake(ctx context.Context, serverAuthority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !c.isClient {
		return nil, nil, errors.New("client handshake called using server transport credentials")
	}

	// Connect to the S2A.
	hsConn, err := service.Dial(c.s2aAddr)
	if err != nil {
		grpclog.Infof("failed to connect to S2A: %v", err)
		return nil, nil, err
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	opts := &handshaker.ClientHandshakerOptions{
		MinTLSVersion:               c.minTLSVersion,
		MaxTLSVersion:               c.maxTLSVersion,
		TLSCiphersuites:             c.tlsCiphersuites,
		TargetIdentities:            c.targetIdentities,
		LocalIdentity:               c.localIdentity,
		TargetName:                  serverAuthority,
		EnsureProcessSessionTickets: c.ensureProcessSessionTickets,
	}
	chs, err := handshaker.NewClientHandshaker(ctx, hsConn, rawConn, c.s2aAddr, opts)
	if err != nil {
		grpclog.Infof("call to handshaker.NewClientHandshaker failed: %v", err)
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			if closeErr := chs.Close(); closeErr != nil {
				grpclog.Infof("close failed unexpectedly: %v", err)
				err = fmt.Errorf("%v: close unexpectedly failed: %v", err, closeErr)
			}
		}
	}()

	secConn, authInfo, err := chs.ClientHandshake(context.Background())
	if err != nil {
		grpclog.Infof("Handshake failed: %v", err)
		return nil, nil, err
	}
	return secConn, authInfo, nil
}

// ServerHandshake initiates a server-side TLS handshake using the S2A.
func (c *s2aTransportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.isClient {
		return nil, nil, errors.New("server handshake called using client transport credentials")
	}

	// Connect to the S2A.
	hsConn, err := service.Dial(c.s2aAddr)
	if err != nil {
		grpclog.Infof("failed to connect to S2A: %v", err)
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	opts := &handshaker.ServerHandshakerOptions{
		MinTLSVersion:   c.minTLSVersion,
		MaxTLSVersion:   c.maxTLSVersion,
		TLSCiphersuites: c.tlsCiphersuites,
		LocalIdentities: c.localIdentities,
	}
	shs, err := handshaker.NewServerHandshaker(ctx, hsConn, rawConn, c.s2aAddr, opts)
	if err != nil {
		grpclog.Infof("call to handshaker.NewServerHandshaker failed: %v", err)
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			if closeErr := shs.Close(); closeErr != nil {
				grpclog.Infof("close failed unexpectedly: %v", err)
				err = fmt.Errorf("%v: close unexpectedly failed: %v", err, closeErr)
			}
		}
	}()

	secConn, authInfo, err := shs.ServerHandshake(context.Background())
	if err != nil {
		grpclog.Infof("Handshake failed: %v", err)
		return nil, nil, err
	}
	return secConn, authInfo, nil
}

func (c *s2aTransportCreds) Info() credentials.ProtocolInfo {
	return *c.info
}

func (c *s2aTransportCreds) Clone() credentials.TransportCredentials {
	info := *c.info
	var localIdentity *commonpb.Identity
	if c.localIdentity != nil {
		localIdentity = proto.Clone(c.localIdentity).(*commonpb.Identity)
	}
	var localIdentities []*commonpb.Identity
	if c.localIdentities != nil {
		localIdentities = make([]*commonpb.Identity, len(c.localIdentities))
		for i, localIdentity := range c.localIdentities {
			localIdentities[i] = proto.Clone(localIdentity).(*commonpb.Identity)
		}
	}
	var targetIdentities []*commonpb.Identity
	if c.targetIdentities != nil {
		targetIdentities = make([]*commonpb.Identity, len(c.targetIdentities))
		for i, targetIdentity := range c.targetIdentities {
			targetIdentities[i] = proto.Clone(targetIdentity).(*commonpb.Identity)
		}
	}
	return &s2aTransportCreds{
		info:             &info,
		minTLSVersion:    c.minTLSVersion,
		maxTLSVersion:    c.maxTLSVersion,
		tlsCiphersuites:  c.tlsCiphersuites,
		localIdentity:    localIdentity,
		localIdentities:  localIdentities,
		targetIdentities: targetIdentities,
		isClient:         c.isClient,
		s2aAddr:          c.s2aAddr,
	}
}

func (c *s2aTransportCreds) OverrideServerName(serverNameOverride string) error {
	c.info.ServerName = serverNameOverride
	return nil
}
