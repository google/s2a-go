load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)

go_library(
  name = "fakes2av2",
  srcs = ["fakes2av2.go"],
  importpath = "github.com/google/s2a-go/internal/v2/fakes2av2",
  testonly = True,
  embedsrcs = [
    "example_cert_key/client_root_cert.pem",
    "example_cert_key/client_root_cert.der",
    "example_cert_key/client_root_key.pem",
    "example_cert_key/server_root_cert.pem",
    "example_cert_key/server_root_cert.der",
    "example_cert_key/server_root_key.pem",
  ],
  deps = [
    "//internal/proto/v2/common_go_proto:common_go_proto",
    "//internal/proto/v2/s2a_context_go_proto:s2a_context_go_proto",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "@org_golang_google_grpc//codes:go_default_library",
  ],
)

go_test(
  name = "fakes2av2_test",
  srcs = ["fakes2av2_test.go"],
  embed = [":fakes2av2"],
  deps = [
    "//internal/proto/common_go_proto:common_go_proto",
    "//internal/proto/v2/common_go_proto:common_go_proto",
    "//internal/proto/v2/s2a_context_go_proto:s2a_context_go_proto",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    "@com_github_google_go_cmp//cmp:go_default_library",
    "@org_golang_google_grpc//codes:go_default_library",
    "@org_golang_google_grpc//credentials/insecure:go_default_library",
    "@org_golang_google_grpc//:go_default_library",
  ],
)
