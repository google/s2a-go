/*
 *
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package main runs an Echo service.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/google/s2a-go/example/echo"
	"github.com/google/s2a-go/internal/v2"
	"google.golang.org/grpc"

	pb "github.com/google/s2a-go/example/proto/echo_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

var (
	port    = flag.String("port", ":8080", "Echo service address port.")
	s2aAddr = flag.String("s2a_addr", "0.0.0.0:61365", "S2A service address.")
)

func runServer(listenPort *string) {
	localIdentities := []*commonpbv1.Identity{
		{
			IdentityOneof: &commonpbv1.Identity_Hostname{
				Hostname: "test_rsa_server_identity",
			},
		},
	}

	// TODO(rmehta19): Use S2A v1 NewServerCreds, specify EnableV2 in ServerOptions.
	creds, err := v2.NewServerCreds(*s2aAddr, localIdentities, s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE)
	if err != nil {
		log.Fatalf("NewClientCreds() failed: %v", err)
	}
	listener, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("Failed to listen on addres %s: %v", *port, err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	log.Printf("Server: started gRPC Echo Server at: %s", *port)
	pb.RegisterEchoServer(s, &echo.Server{})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func main() {
	runServer(port)
}
