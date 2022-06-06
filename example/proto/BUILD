load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_grpc_library")

package(
  default_visibility = ["//example:__subpackages__"],
)

proto_library(
  name = "echo_proto",
  srcs = ["echo.proto"],
)

# Generates Go code of proto messages.
go_proto_library(
  name = "echo_go_proto",
  importpath = "github.com/google/s2a-go/example/proto/echo_go_proto",
  protos = [":echo_proto"],
)

# Generates gRPC services.
go_grpc_library(
  name = "echo_go_grpc_proto",
  importpath = "github.com/google/s2a-go/example/proto/echo_go_grpc_proto",
  protos = [":echo_proto"],
)
