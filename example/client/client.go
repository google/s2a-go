package main

import (
	"log"
	"time"
	"flag"
	"context"
	"github.com/google/s2a-go/internal/v2"
	"google.golang.org/grpc"
	pb "github.com/google/s2a-go/example/proto/echo_go_proto"
)

const (
	defaultTimeout = 10.0 * time.Second
)

var (
	serverAddr = flag.String("server_addr", "0.0.0.0:8080", "Echo service address.")
)

func runClient(serverAddr *string) {
	creds, err := v2.NewClientCreds("0.0.0.0:8008")
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
