#!/bin/bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
export PATH="$PATH:$(go env GOPATH)/bin"

# Regenerate the S2A protos.
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
      internal/proto/common.proto internal/proto/s2a.proto internal/proto/s2a_context.proto

mkdir -p internal/proto/common_go_proto
mv internal/proto/common.pb.go internal/proto/common_go_proto/common.pb.go

mkdir -p internal/proto/s2a_go_proto
mv internal/proto/s2a.pb.go internal/proto/s2a_go_proto/s2a.pb.go
mv internal/proto/s2a_grpc.pb.go internal/proto/s2a_go_proto/s2a_grpc.pb.go

mkdir -p internal/proto/s2a_context_go_proto
mv internal/proto/s2a_context.pb.go internal/proto/s2a_context_go_proto/s2a_context.pb.go

# Regenerate the example protos.
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
      internal/proto/examples/helloworld.proto

mkdir -p internal/proto/examples/helloworld_go_proto
mv internal/proto/examples/helloworld.pb.go internal/proto/examples/helloworld_go_proto/helloworld.pb.go
mv internal/proto/examples/helloworld_grpc.pb.go internal/proto/examples/helloworld_go_proto/helloworld_grpc.pb.go

