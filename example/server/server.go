package main

import (
	"flag"
	"net"
	"log"
	"github.com/google/s2a-go/example/echo"
	"github.com/google/s2a-go/internal/v2"
	"google.golang.org/grpc"
	pb "github.com/google/s2a-go/example/proto/echo_go_proto"
)

var (
	port = flag.String("port", ":8080", "Echo service address port.")
)

func runServer(listenPort *string) {
	creds, err := v2.NewServerCreds("0.0.0.0:8008")
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
