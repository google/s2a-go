// Package main runs an S2Av2 service.
package main

import (
	"flag"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	"github.com/google/s2a-go/internal/v2/fakes2av2"
	"google.golang.org/grpc"
	"log"
	"net"
)

var (
	port = flag.String("port", ":8008", "Fake S2Av2 server address port.")
)

func runFakeS2Av2Server(listenPort *string) {
	listener, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", listener.Addr().String(), err)
	}
	s := grpc.NewServer()
	log.Printf("Server: started gRPC Fake S2Av2 Server at port: %s", listener.Addr())
	s2av2pb.RegisterS2AServiceServer(s, &fakes2av2.Server{})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	runFakeS2Av2Server(port)
}
