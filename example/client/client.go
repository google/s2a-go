// Package main establishes a connection with an Echo service.
package main

import (
	"context"
	"flag"
	pb "github.com/google/s2a-go/example/proto/echo_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	"github.com/google/s2a-go/internal/v2"
	"google.golang.org/grpc"
	"log"
	"time"
)

const (
	defaultTimeout = 10.0 * time.Second
)

var (
	serverAddr = flag.String("server_addr", "0.0.0.0:8080", "Echo service address.")
	s2aAddr    = flag.String("s2a_addr", "0.0.0.0:61366", "S2A service address.")
)

func runClient(serverAddr *string) {
	// TODO(rmehta19): Use S2A v1 NewClientCreds, specify EnableV2 in ClientOptions.
	creds, err := v2.NewClientCreds(*s2aAddr, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_client_identity",
		},
	}, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
	if err != nil {
		log.Fatalf("NewClientCreds() failed: %v", err)
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithReturnConnectionError(),
		grpc.WithDisableRetry(),
		grpc.WithBlock(),
	}
	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		log.Fatalf("Client: failed to connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewEchoClient(conn)
	log.Printf("Client: connected to: %s", *serverAddr)
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	msg := "Hello S2Av2 user!"
	r, err := c.Echo(ctx, &pb.EchoRequest{Msg: msg})
	if err != nil {
		log.Fatalf("Client: failed to send echo message: %v", err)
	}
	log.Printf("Client: received message from server: %s", r.GetMsg())
}

func main() {
	runClient(serverAddr)
}
