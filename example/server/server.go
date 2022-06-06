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
	listenPort = flag.String("listen_port", ":8080", "Echo service address port.")
)

func runServer(listenPort *string) {
	creds, err := v2.NewServerCreds()
	listener, err := net.Listen("tcp", *listenPort)
	if err != nil {
		log.Fatalf("failed to listen on addres %s: %v", *listenPort, err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	log.Printf("Server: started gRPC Echo Server at: %s", *listenPort)
	pb.RegisterEchoServer(s, &echo.Server{})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	runServer(listenPort)
}
