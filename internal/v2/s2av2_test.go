package v2

import (
	"context"
	"github.com/google/go-cmp/cmp"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
	"github.com/google/s2a-go/internal/tokenmanager"
	"google.golang.org/protobuf/testing/protocmp"
	"os"
	"testing"

	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

var (
	fakes2av2Address = "0.0.0.0:0"
)

// TODO(rmehta19): Consider adding unit tests to test success of ClientHandshake
// and ServerHandshake. Current testing of success is through use of
// example/server, example/client and internal/v2/fakes2av2_server.

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
			c, err := NewClientCreds(fakes2av2Address, &commonpbv1.Identity{
				IdentityOneof: &commonpbv1.Identity_Hostname{
					Hostname: "test_rsa_client_identity",
				},
			}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
			if err != nil {
				t.Fatalf("NewClientCreds() failed: %v", err)
			}
			if got, want := c.Info().SecurityProtocol, s2aSecurityProtocol; got != want {
				t.Errorf("c.Info().SecurityProtocol = %v, want %v", got, want)
			}
			_, ok := c.(*s2av2TransportCreds)
			if !ok {
				t.Fatal("the created creds is not of type s2av2TransportCreds")
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
			var localIdentities []*commonpbv1.Identity
			localIdentities = append(localIdentities, &commonpbv1.Identity{
				IdentityOneof: &commonpbv1.Identity_Hostname{
					Hostname: "test_rsa_server_identity",
				},
			})
			c, err := NewServerCreds(fakes2av2Address, localIdentities, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
			if err != nil {
				t.Fatalf("NewServerCreds() failed: %v", err)
			}
			if got, want := c.Info().SecurityProtocol, s2aSecurityProtocol; got != want {
				t.Errorf("c.Info().SecurityProtocol = %v, want %v", got, want)
			}
			_, ok := c.(*s2av2TransportCreds)
			if !ok {
				t.Fatal("the created creds is not of type s2av2TransportCreds")
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
	c, err := NewClientCreds(fakes2av2Address, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
	if err != nil {
		t.Fatalf("NewClientCreds() failed: %v", err)
	}
	info := c.Info()
	if got, want := info.SecurityProtocol, "s2av2"; got != want {
		t.Errorf("info.SecurityProtocol=%v, want %v", got, want)
	}
}

func TestCloneClient(t *testing.T) {
	os.Setenv("S2A_ACCESS_TOKEN", "TestCloneClient_s2a_access_token")
	c, err := NewClientCreds(fakes2av2Address, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
	if err != nil {
		t.Fatalf("NewClientCreds() failed: %v", err)
	}
	cc := c.Clone()
	s2av2Creds, ok := c.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("the created creds is not of type s2av2TransportCreds")
	}
	s2av2CloneCreds, ok := cc.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("the created clone creds is not of type s2aTransportCreds")
	}
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		} else {
			return false
		}
	})), true; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
	// Change the values and verify the creds were deep copied.
	s2av2CloneCreds.info.SecurityProtocol = "s2a"
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		} else {
			return false
		}
	})), false; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
}

func TestCloneServer(t *testing.T) {
	os.Setenv("S2A_ACCESS_TOKEN", "TestCloneServer_s2a_access_token")
	var localIdentities []*commonpbv1.Identity
	localIdentities = append(localIdentities, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_server_identity",
		},
	})
	c, err := NewServerCreds(fakes2av2Address, localIdentities, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
	if err != nil {
		t.Fatalf("NewServerCreds() failed: %v", err)
	}
	cc := c.Clone()
	s2av2Creds, ok := c.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("the created creds is not of type s2av2TransportCreds")
	}
	s2av2CloneCreds, ok := cc.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("the created clone creds is not of type s2aTransportCreds")
	}
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		} else {
			return false
		}
	})), true; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
	// Change the values and verify the creds were deep copied.
	s2av2CloneCreds.info.SecurityProtocol = "s2a"
	if got, want := cmp.Equal(s2av2Creds, s2av2CloneCreds, protocmp.Transform(), cmp.AllowUnexported(s2av2TransportCreds{}), cmp.Comparer(func(x, y tokenmanager.AccessTokenManager) bool {
		xToken, err := x.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		yToken, err := y.DefaultToken()
		if err != nil {
			t.Errorf("failed to compare cloned creds: %v", err)
		}
		if xToken == yToken {
			return true
		} else {
			return false
		}
	})), false; got != want {
		t.Errorf("cmp.Equal(%+v, %+v) = %v, want %v", s2av2Creds, s2av2CloneCreds, got, want)
	}
}

func TestOverrideServerName(t *testing.T) {
	// Setup test.
	os.Setenv("S2A_ACCESS_TOKEN", "TestOverrideServerName_s2a_access_token")
	c, err := NewClientCreds(fakes2av2Address, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
	s2av2Creds, ok := c.(*s2av2TransportCreds)
	if !ok {
		t.Fatal("the created creds is not of type s2av2TransportCreds")
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
