package tlsconfigstore

import (
	"net"
	"log"
	"sync"
	"time"
	"context"
	"testing"
	"crypto/tls"
	"bytes"

	_ "embed"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

const (
	defaultTimeout = 10.0 * time.Second
)

var (
	//go:embed example_cert_key/client_cert.pem
	clientCertpem []byte
	//go:embed example_cert_key/server_cert.pem
	serverCertpem []byte
	//go:embed example_cert_key/client_key.pem
	clientKeypem []byte
	//go:embed example_cert_key/server_key.pem
	serverKeypem []byte
)

func startFakeS2Av2Server(wg *sync.WaitGroup) (stop func(), err error) {
	// Pick unused port.
	listener, err := net.Listen("tcp", ":8008")
	if err != nil {
		log.Fatalf("failed to listen on address %s: %v", listener.Addr().String(), err)
	}
	s := grpc.NewServer()
	log.Printf("Server: started gRPC fake S2Av2 Server on address: %s", listener.Addr().String())
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{})
	go func() {
		wg.Done()
		if err := s.Serve(listener); err != nil {
			log.Printf("failed to serve: %v", err)
		}
	}()
	return func() { s.Stop()}, nil
}

// TODO(rmehta19): In Client and Server test, verify contents of config.RootCAs once x509.CertPool.Equal function is officially released : https://cs.opensource.google/go/go/+/4aacb7ff0f103d95a724a91736823f44aa599634 .

// TestTLSConfigStoreClient runs unit tests for GetTlsConfigurationForClient.
func TestTLSConfigStoreClient(t *testing.T) {
	// Setup for static client test.
	cert, err := tls.X509KeyPair(clientCertpem, clientKeypem)
	if err != nil {
		t.Errorf("tls.X509KeyPair failed: %v", err)
	}

	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		log.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	// Create stream to S2Av2.
	opts := []grpc.DialOption {
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithReturnConnectionError(),
		grpc.WithBlock(),
	}
	conn, err := grpc.Dial("0.0.0.0:8008", opts...)
	if err != nil {
		log.Fatalf("Client: failed to connect: %v", err)
	}
	defer conn.Close()
	c := s2av2pb.NewS2AServiceClient(conn)
	log.Printf("Client: connected to: %s", "0.0.0.0:8008")
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Setup bidrectional streaming session.
	callOpts := []grpc.CallOption{}
	cstream, err := c.SetUpSession(ctx, callOpts...)
	if err != nil  {
		log.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
	}
	log.Printf("Client: set up bidirectional streaming RPC session.")

	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		ServerName	            string
		InsecureSkipVerify          bool
		ClientSessionCache	    tls.ClientSessionCache
		MinVersion	            uint16
		MaxVersion		    uint16
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			ServerName: "host",
			InsecureSkipVerify: true,
			ClientSessionCache: nil,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			config := GetTlsConfigurationForClient(tc.ServerName, cstream)
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got, want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			if got, want := config.InsecureSkipVerify, tc.InsecureSkipVerify; got != want {
				t.Errorf("config.InsecureSkipVerify = %v, want %v", got, want)
			}
			if got, want := config.ClientSessionCache, tc.ClientSessionCache; got != want {
				t.Errorf("config.ClientSessionCache = %v, want %v", got, want)
			}
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
		})
	}
	stop()
}

// TestTLSConfigStoreServer runs unit tests for GetTLSConfigurationForServer.
func TestTLSConfigStoreServer(t *testing.T) {
	// Setup for static server test.
	cert, err := tls.X509KeyPair(serverCertpem, serverKeypem)
	if err != nil {
		t.Errorf("tls.X509KeyPair failed: %v", err)
	}

	// Start up fake S2Av2 server.
	var wg sync.WaitGroup
	wg.Add(1)
	stop, err := startFakeS2Av2Server(&wg)
	wg.Wait()
	if err != nil {
		log.Fatalf("error starting fake S2Av2 Server: %v", err)
	}

	// Create stream to S2Av2.
	opts := []grpc.DialOption {
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithReturnConnectionError(),
		grpc.WithBlock(),
	}
	conn, err := grpc.Dial("0.0.0.0:8008", opts...)
	if err != nil {
		log.Fatalf("Client: failed to connect: %v", err)
	}
	defer conn.Close()
	c := s2av2pb.NewS2AServiceClient(conn)
	log.Printf("Client: connected to: %s", "0.0.0.0:8008")
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Setup bidrectional streaming session.
	callOpts := []grpc.CallOption{}
	cstream, err := c.SetUpSession(ctx, callOpts...)
	if err != nil  {
		log.Fatalf("Client: failed to setup bidirectional streaming RPC session: %v", err)
	}
	log.Printf("Client: set up bidirectional streaming RPC session.")

	for _, tc := range []struct {
		description		    string
		Certificates                []tls.Certificate
		ClientAuth		    tls.ClientAuthType
		InsecureSkipVerify          bool
		MinVersion	            uint16
		MaxVersion		    uint16
	}{
		{
			description: "static",
			Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAndVerifyClientCert,
			InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			config := GetTlsConfigurationForServer(cstream)
			if got, want := config.Certificates[0].Certificate[0], tc.Certificates[0].Certificate[0]; !bytes.Equal(got,want) {
				t.Errorf("config.Certificates[0].Certificate[0] = %v, want %v", got, want)
			}
			if got, want := config.ClientAuth, tc.ClientAuth; got != want {
				t.Errorf("config.ClientAuth = %v, want %v", got, want)
			}
			if got, want := config.InsecureSkipVerify, tc.InsecureSkipVerify; got != want {
				t.Errorf("config.InsecureSkipVerify = %v, want %v", got, want)
			}
			if got, want := config.MinVersion, tc.MinVersion; got != want {
				t.Errorf("config.MinVersion = %v, want %v", got, want)
			}
			if got, want := config.MaxVersion, tc.MaxVersion; got != want {
				t.Errorf("config.MaxVersion = %v, want %v", got, want)
			}
		})
	}
	stop()
}
