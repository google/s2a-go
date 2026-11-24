/*
 *
 * Copyright 2022 Google LLC
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

package v2

import (
	"bytes"
	"context"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/s2a-go/fallback"
	"github.com/google/s2a-go/internal/tokenmanager"
	"github.com/google/s2a-go/stream"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/testing/protocmp"

	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

var (
	fakes2av2Address = "0.0.0.0:0"
)

func TestNewClientCreds(t *testing.T) {
	os.Setenv("S2A_ACCESS_TOKEN", "TestNewClientCreds_s2a_access_token")
	for _, tc := range []struct {
		description string
	}{
		{
			description: "static",
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			c, err := NewClientCreds(fakes2av2Address, nil, &commonpb.Identity{
				IdentityOneof: &commonpb.Identity_Hostname{
					Hostname: "test_rsa_client_identity",
				},
			}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, nil, nil, nil)
			if err != nil {
				t.Fatalf("NewClientCreds() failed: %v", err)
			}
			if got, want := c.Info().SecurityProtocol, s2aSecurityProtocol; got != want {
				t.Errorf("c.Info().SecurityProtocol = %v, want %v", got, want)
			}
			_, ok := c.(*s2av2TransportCreds)
			if !ok {
				t.Fatal("The created creds is not of type s2av2TransportCreds")
			}
		})
	}
}

func TestNewServerCreds(t *testing.T) {
	os.Setenv("S2A_ACCESS_TOKEN", "TestNewServerCreds_s2a_access_token")
	for _, tc := range []struct {
		description string
	}{
		{
			description: "static",
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			localIdentities := []*commonpb.Identity{
				{
					IdentityOneof: &commonpb.Identity_Hostname{
						Hostname: "test_rsa_server_identity",
					},
				},
			}
			c, err := NewServerCreds(fakes2av2Address, nil, localIdentities, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, nil)
			if err != nil {
				t.Fatalf("NewServerCreds() failed: %v", err)
			}
			if got, want := c.Info().SecurityProtocol, s2aSecurityProtocol; got != want {
				t.Errorf("c.Info().SecurityProtocol = %v, want %v", got, want)
			}
			_, ok := c.(*s2av2TransportCreds)
			if !ok {
				t.Fatal("The created creds is not of type s2av2TransportCreds")
			}
		})
	}
}

func TestClientHandshakeFail(t *testing.T) {
	cc := &s2av2TransportCreds{isClient: false}
	if _, _, err := cc.ClientHandshake(context.Background(), "", nil); err == nil {
		t.Errorf("c.ClientHandshake(nil, \"\", nil) should fail with incorrect transport credentials")
	}
}

func TestServerHandshakeFail(t *testing.T) {
	sc := &s2av2TransportCreds{isClient: true}
	if _, _, err := sc.ServerHandshake(nil); err == nil {
		t.Errorf("c.ServerHandshake(nil) should fail with incorrect transport credentials")
	}
}

func TestInfo(t *testing.T) {
	os.Setenv("S2A_ACCESS_TOKEN", "TestInfo_s2a_access_token")
	c, err := NewClientCreds(fakes2av2Address, nil, &commonpb.Identity{
		IdentityOneof: &commonpb.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewClientCreds() failed: %v", err)
	}
	info := c.Info()
	if got, want := info.SecurityProtocol, "tls"; got != want {
		t.Errorf("info.SecurityProtocol=%v, want %v", got, want)
	}
}

func TestCloneClient(t *testing.T) {
	os.Setenv("S2A_ACCESS_TOKEN", "TestCloneClient_s2a_access_token")
	fallbackFunc, err := fallback.DefaultFallbackClientHandshakeFunc("example.com")
	if err != nil {
		t.Errorf("error creating fallback handshake function: %v", err)
	}
	c, err := NewClientCreds(fakes2av2Address, nil, &commonpb.Identity{
		IdentityOneof: &commonpb.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, fallbackFunc, nil, nil)
	if err != nil {
		t.Fatalf("NewClientCreds() failed: %v", err)
	}
	cc := c.Clone()
	s2av2Creds, ok := c.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("The created creds is not of type s2av2TransportCreds")
	}
	s2av2CloneCreds, ok := cc.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("The created clone creds is not of type s2aTransportCreds")
	}
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		}
		return false
	}), cmp.Comparer(func(x, y fallback.ClientHandshake) bool {
		return reflect.ValueOf(x) == reflect.ValueOf(y)
	})), true; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
	// Change the values and verify the creds were deep copied.
	s2av2CloneCreds.info.SecurityProtocol = "s2a"
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		}
		return false
	})), false; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
}

func TestCloneServer(t *testing.T) {
	os.Setenv("S2A_ACCESS_TOKEN", "TestCloneServer_s2a_access_token")
	localIdentities := []*commonpb.Identity{
		{
			IdentityOneof: &commonpb.Identity_Hostname{
				Hostname: "test_rsa_server_identity",
			},
		},
	}
	c, err := NewServerCreds(fakes2av2Address, nil, localIdentities, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, nil)
	if err != nil {
		t.Fatalf("NewServerCreds() failed: %v", err)
	}
	cc := c.Clone()
	s2av2Creds, ok := c.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("The created creds is not of type s2av2TransportCreds")
	}
	s2av2CloneCreds, ok := cc.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("The created clone creds is not of type s2aTransportCreds")
	}
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		}
		return false
	})), true; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
	// Change the values and verify the creds were deep copied.
	s2av2CloneCreds.info.SecurityProtocol = "s2a"
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("Failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		}
		return false
	})), false; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
}

type fakeTransportCreds struct {
	info   credentials.ProtocolInfo
	cloned bool
}

func (f *fakeTransportCreds) ClientHandshake(_ context.Context, _ string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return rawConn, nil, nil
}

func (f *fakeTransportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return rawConn, nil, nil
}

func (f *fakeTransportCreds) Info() credentials.ProtocolInfo {
	return f.info
}

func (f *fakeTransportCreds) Clone() credentials.TransportCredentials {
	return &fakeTransportCreds{
		info:   f.info,
		cloned: true,
	}
}

func (f *fakeTransportCreds) OverrideServerName(serverNameOverride string) error {
	f.info.ServerName = serverNameOverride
	return nil
}

func TestCloneClientPreservesOptionalFields(t *testing.T) {
	t.Setenv("S2A_ACCESS_TOKEN", "TestCloneClientPreservesOptionalFields_token")
	fallbackFunc, err := fallback.DefaultFallbackClientHandshakeFunc("example.com")
	if err != nil {
		t.Fatalf("DefaultFallbackClientHandshakeFunc() failed: %v", err)
	}
	origTC := &fakeTransportCreds{
		info: credentials.ProtocolInfo{
			SecurityProtocol: "tls",
			ServerName:       "s2a.example.com",
		},
	}
	streamCalled := false
	getStream := func(context.Context, string, ...string) (stream.S2AStream, error) {
		streamCalled = true
		return s2ATestStream{debug: "cloned client stream"}, nil
	}
	origPolicy := []byte("test_server_authz_policy")

	c, err := NewClientCreds(fakes2av2Address, origTC, &commonpb.Identity{
		IdentityOneof: &commonpb.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, fallbackFunc, getStream, origPolicy)
	if err != nil {
		t.Fatalf("NewClientCreds() failed: %v", err)
	}

	cc := c.Clone()
	s2av2Creds, ok := c.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("created creds is not of type *s2av2TransportCreds")
	}
	s2av2CloneCreds, ok := cc.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("cloned creds is not of type *s2av2TransportCreds")
	}

	cmpOpts := []cmp.Option{
		protocmp.Transform(),
		cmp.AllowUnexported(s2av2TransportCreds{}),
		cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
			xToken, err := x.DefaultToken()
			if err != nil {
				t.Errorf("x.DefaultToken() failed: %v", err)
			}
			yToken, err := y.DefaultToken()
			if err != nil {
				t.Errorf("y.DefaultToken() failed: %v", err)
			}
			return xToken == yToken
		}),
		cmp.Comparer(func(x, y fallback.ClientHandshake) bool {
			if x == nil || y == nil {
				return x == nil && y == nil
			}
			return reflect.ValueOf(x).Pointer() == reflect.ValueOf(y).Pointer()
		}),
		cmp.Comparer(func(x, y stream.GetS2AStream) bool {
			if x == nil || y == nil {
				return x == nil && y == nil
			}
			return reflect.ValueOf(x).Pointer() == reflect.ValueOf(y).Pointer()
		}),
		cmp.Comparer(func(x, y *fakeTransportCreds) bool {
			if x == nil || y == nil {
				return x == nil && y == nil
			}
			return x.info == y.info
		}),
	}
	if diff := cmp.Diff(s2av2Creds, s2av2CloneCreds, cmpOpts...); diff != "" {
		t.Errorf("Clone() mismatch (-want +got):\n%s", diff)
	}

	// Verify transportCreds was deep-copied via Clone().
	clonedTC, ok := s2av2CloneCreds.transportCreds.(*fakeTransportCreds)
	if !ok {
		t.Fatalf("s2av2CloneCreds.transportCreds = %T, want *fakeTransportCreds", s2av2CloneCreds.transportCreds)
	}
	if clonedTC == origTC {
		t.Errorf("s2av2CloneCreds.transportCreds points to original instance; want independent clone")
	}
	if !clonedTC.cloned {
		t.Errorf("clonedTC.cloned = false, want true")
	}
	if err := clonedTC.OverrideServerName("mutated.example.com"); err != nil {
		t.Fatalf("clonedTC.OverrideServerName() failed: %v", err)
	}
	if got, want := origTC.Info().ServerName, "s2a.example.com"; got != want {
		t.Errorf("origTC.Info().ServerName = %q, want %q", got, want)
	}

	// Verify getS2AStream was preserved and is callable on the clone.
	if s2av2CloneCreds.getS2AStream == nil {
		t.Fatal("s2av2CloneCreds.getS2AStream = nil, want non-nil")
	}
	s2aStream, err := createStream(context.Background(), fakes2av2Address, s2av2CloneCreds.transportCreds, s2av2CloneCreds.getS2AStream)
	if err != nil {
		t.Fatalf("createStream() with cloned creds failed: %v", err)
	}
	if !streamCalled {
		t.Errorf("streamCalled = false, want true")
	}
	if gotStream, ok := s2aStream.(s2ATestStream); !ok || gotStream.debug != "cloned client stream" {
		t.Errorf("createStream() = %#v, want s2ATestStream{debug: %q}", s2aStream, "cloned client stream")
	}

	// Verify serverAuthorizationPolicy was deep-copied.
	if got, want := s2av2CloneCreds.serverAuthorizationPolicy, []byte("test_server_authz_policy"); !bytes.Equal(got, want) {
		t.Errorf("s2av2CloneCreds.serverAuthorizationPolicy = %q, want %q", got, want)
	}
	s2av2CloneCreds.serverAuthorizationPolicy[0] = 'X'
	if got, want := string(s2av2Creds.serverAuthorizationPolicy), "test_server_authz_policy"; got != want {
		t.Errorf("mutating clone policy modified original: got %q, want %q", got, want)
	}

	// Verify non-nil empty serverAuthorizationPolicy stays non-nil on clone.
	emptyPolicyCreds, err := NewClientCreds(fakes2av2Address, nil, nil, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, nil, nil, []byte{})
	if err != nil {
		t.Fatalf("NewClientCreds() with empty policy failed: %v", err)
	}
	emptyPolicyClone := emptyPolicyCreds.Clone().(*s2av2TransportCreds)
	if emptyPolicyClone.serverAuthorizationPolicy == nil || len(emptyPolicyClone.serverAuthorizationPolicy) != 0 {
		t.Errorf("emptyPolicyClone.serverAuthorizationPolicy = %#v, want non-nil empty slice", emptyPolicyClone.serverAuthorizationPolicy)
	}
}

func TestCloneServerPreservesOptionalFields(t *testing.T) {
	t.Setenv("S2A_ACCESS_TOKEN", "TestCloneServerPreservesOptionalFields_token")
	origTC := &fakeTransportCreds{
		info: credentials.ProtocolInfo{
			SecurityProtocol: "tls",
			ServerName:       "s2a.example.com",
		},
	}
	streamCalled := false
	getStream := func(context.Context, string, ...string) (stream.S2AStream, error) {
		streamCalled = true
		return s2ATestStream{debug: "cloned server stream"}, nil
	}
	localIdentities := []*commonpb.Identity{
		{
			IdentityOneof: &commonpb.Identity_Hostname{
				Hostname: "test_rsa_server_identity",
			},
		},
	}

	c, err := NewServerCreds(fakes2av2Address, origTC, localIdentities, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, getStream)
	if err != nil {
		t.Fatalf("NewServerCreds() failed: %v", err)
	}

	cc := c.Clone()
	s2av2CloneCreds, ok := cc.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("cloned creds is not of type *s2av2TransportCreds")
	}

	clonedTC, ok := s2av2CloneCreds.transportCreds.(*fakeTransportCreds)
	if !ok {
		t.Fatalf("s2av2CloneCreds.transportCreds = %T, want *fakeTransportCreds", s2av2CloneCreds.transportCreds)
	}
	if clonedTC == origTC {
		t.Errorf("s2av2CloneCreds.transportCreds points to original instance; want independent clone")
	}
	if !clonedTC.cloned {
		t.Errorf("clonedTC.cloned = false, want true")
	}
	if err := clonedTC.OverrideServerName("mutated.example.com"); err != nil {
		t.Fatalf("clonedTC.OverrideServerName() failed: %v", err)
	}
	if got, want := origTC.Info().ServerName, "s2a.example.com"; got != want {
		t.Errorf("origTC.Info().ServerName = %q, want %q", got, want)
	}

	if s2av2CloneCreds.getS2AStream == nil {
		t.Fatal("s2av2CloneCreds.getS2AStream = nil, want non-nil")
	}
	s2aStream, err := createStream(context.Background(), fakes2av2Address, s2av2CloneCreds.transportCreds, s2av2CloneCreds.getS2AStream)
	if err != nil {
		t.Fatalf("createStream() with cloned server creds failed: %v", err)
	}
	if !streamCalled {
		t.Errorf("streamCalled = false, want true")
	}
	if gotStream, ok := s2aStream.(s2ATestStream); !ok || gotStream.debug != "cloned server stream" {
		t.Errorf("createStream() = %#v, want s2ATestStream{debug: %q}", s2aStream, "cloned server stream")
	}
}

func TestOverrideServerName(t *testing.T) {
	// Setup test.
	os.Setenv("S2A_ACCESS_TOKEN", "TestOverrideServerName_s2a_access_token")
	c, err := NewClientCreds(fakes2av2Address, nil, &commonpb.Identity{
		IdentityOneof: &commonpb.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE, nil, nil, nil)
	s2av2Creds, ok := c.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("The created creds is not of type s2av2TransportCreds")
	}
	if err != nil {
		t.Fatalf("NewClientCreds() failed: %v", err)
	}
	if got, want := c.Info().ServerName, ""; got != want {
		t.Errorf("c.Info().ServerName = %v, want %v", got, want)
	}
	if got, want := s2av2Creds.serverName, ""; got != want {
		t.Errorf("c.serverName = %v, want %v", got, want)
	}
	for _, tc := range []struct {
		description    string
		override       string
		wantServerName string
		expectError    bool
	}{
		{
			description:    "empty string",
			override:       "",
			wantServerName: "",
		},
		{
			description:    "host only",
			override:       "server.name",
			wantServerName: "server.name",
		},
		{
			description:    "invalid syntax",
			override:       "server::",
			wantServerName: "server::",
		},
		{
			description:    "split host port",
			override:       "host:port",
			wantServerName: "host",
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			c.OverrideServerName(tc.override)
			if got, want := c.Info().ServerName, tc.wantServerName; got != want {
				t.Errorf("c.Info().ServerName = %v, want %v", got, want)
			}
			if got, want := s2av2Creds.serverName, tc.wantServerName; got != want {
				t.Errorf("c.serverName = %v, want %v", got, want)
			}
		})
	}
}

type s2ATestStream struct {
	debug string
}

func (x s2ATestStream) Send(m *s2av2pb.SessionReq) error {
	return nil
}

func (x s2ATestStream) Recv() (*s2av2pb.SessionResp, error) {
	return &s2av2pb.SessionResp{
		RespOneof: &s2av2pb.SessionResp_GetTlsConfigurationResp{
			GetTlsConfigurationResp: &s2av2pb.GetTlsConfigurationResp{
				TlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration_{
					ClientTlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration{
						MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
						MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
					},
				},
			},
		},
	}, nil
}

func (x s2ATestStream) CloseSend() error {
	return nil
}

func TestCreateStream(t *testing.T) {
	for _, tc := range []struct {
		description string
	}{
		{
			description: "static",
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			s2AStream, err := createStream(context.TODO(), "fake address", nil, func(context.Context, string, ...string) (stream.S2AStream, error) {
				return s2ATestStream{debug: "test s2a stream"}, nil
			})
			if err != nil {
				t.Fatalf("New S2AStream failed: %v", err)
			}
			testStream, ok := s2AStream.(s2ATestStream)
			if !ok {
				t.Fatal("The created stream is not of type s2ATestStream")
			}
			if testStream.debug != "test s2a stream" {
				t.Errorf("The created stream is not the intended stream")
			}
		})
	}
}

func TestGetS2ATimeout(t *testing.T) {
	oldEnvValue := os.Getenv(s2aTimeoutEnv)
	defer os.Setenv(s2aTimeoutEnv, oldEnvValue)

	// Unset the environment var
	os.Unsetenv(s2aTimeoutEnv)
	if got, want := GetS2ATimeout(), defaultS2ATimeout; got != want {
		t.Fatalf("GetS2ATimeout should return default if S2A_TIMEOUT is not set")
	}

	// Set the environment var to empty string
	os.Setenv(s2aTimeoutEnv, "")
	if got, want := GetS2ATimeout(), defaultS2ATimeout; got != want {
		t.Fatalf("GetS2ATimeout should return default if S2A_TIMEOUT is set to empty string")
	}

	// Set a valid duration string
	os.Setenv(s2aTimeoutEnv, "5s")
	if got, want := GetS2ATimeout(), 5*time.Second; got != want {
		t.Fatalf("expected timeout to be 5s")
	}

	// Set an invalid duration string
	os.Setenv(s2aTimeoutEnv, "5abc")
	if got, want := GetS2ATimeout(), defaultS2ATimeout; got != want {
		t.Fatalf("expected timeout to be default if the set timeout is invalid")
	}
}
