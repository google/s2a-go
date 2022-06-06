load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
  default_visibility = ["//example:__subpackages__"],
)

go_library(
  name = "echo_go_proto",
  srcs = [
    "echo.pb.go",
    "echo_grpc.pb.go",
  ],
  importpath = "github.com/google/s2a-go/example/proto/echo_go_proto",
  deps = [
    "@org_golang_google_grpc//:go_default_library",
    "@org_golang_google_grpc//codes:go_default_library",
    "@org_golang_google_grpc//status:go_default_library",
    "@org_golang_google_protobuf//reflect/protoreflect:go_default_library",
    "@org_golang_google_protobuf//runtime/protoimpl:go_default_library",
  ],
)
