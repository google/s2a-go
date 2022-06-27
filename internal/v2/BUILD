# Description: gRPC transport credentials that use S2Av2
load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//:__subpackages__"],
)

go_library(
  name = "v2",
  srcs = [
    "s2av2.go",
  ],
  importpath = "github.com/google/s2a-go/internal/v2",
  deps = [
    "//internal/handshaker/service",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "//internal/v2/tls_config_store",
    "@org_golang_google_grpc//credentials:go_default_library",
    "@org_golang_google_grpc//:go_default_library",
  ]
)

go_test(
  name = "v2_test",
  srcs = [
    "s2av2_test.go",
    "s2av2_e2e_test.go",
  ],
  embed = [":v2"],
  deps = [
    "//internal/proto/examples/helloworld_go_proto:helloworld_go_proto",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "//internal/v2/fakes2av2",
    "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    "@com_github_google_go_cmp//cmp:go_default_library",
    "@org_golang_google_grpc//grpclog:go_default_library",
  ],
)
