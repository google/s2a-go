// Package main runs an Echo service.
package main

import (
	"flag"
	"github.com/google/s2a-go/example/echo"
	pb "github.com/google/s2a-go/example/proto/echo_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	"github.com/google/s2a-go/internal/v2"
	"google.golang.org/grpc"
	"log"
	"net"
)

var (
	port    = flag.String("port", ":8080", "Echo service address port.")
	s2aAddr = flag.String("s2a_addr", "0.0.0.0:61365", "S2A service address.")
)

func runServer(listenPort *string) {
	var localIdentities []*commonpbv1.Identity
	localIdentities = append(localIdentities, &commonpbv1.Identity{
		IdentityOneof: &commonpbv1.Identity_Hostname{
			Hostname: "test_rsa_server_identity",
		},
	})

	// TODO(rmehta19): Use S2A v1 NewServerCreds, specify EnableV2 in ServerOptions.
	creds, err := v2.NewServerCreds(*s2aAddr, localIdentities, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
	if err != nil {
		log.Fatalf("NewClientCreds() failed: %v", err)
	}
	listener, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("failed to listen on addres %s: %v", *port, err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	log.Printf("Server: started gRPC Echo Server at: %s", *port)
	pb.RegisterEchoServer(s, &echo.Server{})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	runServer(port)
}
