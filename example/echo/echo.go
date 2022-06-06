// Package echo contains the libraries for running an Echo server.
package echo

import (
	"context"

	pb "github.com/google/s2a-go/example/proto/echo_go_proto"
)

// Server is an echo server used for testing.
type Server struct {
	pb.UnimplementedEchoServer
}

// Echo uses the message, Msg, in EchoRequest to formulate EchoResponse.
func (s *Server) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	return &pb.EchoResponse{Msg: req.GetMsg()}, nil
}
