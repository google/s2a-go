package main

import (
	"net"
	"flag"
	"log"
	"google.golang.org/grpc"
	"github.com/google/s2a-go/internal/v2/fake_s2av2"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

var (
	listenPort = flag.String("listen_port", ":8080", "Fake S2Av2 service address port.")
)

func runFakeS2Av2Server(listenPort *string) {
	listener, err := net.Listen("tcp", *listenPort)
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", *listenPort, err)
	}
	s := grpc.NewServer()
	log.Printf("Server: started gRPC Fake S2Av2 Server at port: %s", *listenPort)
	s2av2pb.RegisterS2AServiceServer(s, &fake_s2av2.Server{})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	runFakeS2Av2Server(listenPort)
}
