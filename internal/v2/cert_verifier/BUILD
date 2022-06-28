load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)


go_library(
  name = "cert_verifier",
  srcs = ["cert_verifier.go"],
  importpath = "github.com/google/s2a-go/internal/v2/cert_verifier",
  deps = [
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "@org_golang_google_grpc//codes:go_default_library",
  ],
)

go_test(
  name = "cert_verifier_test",
  srcs = ["cert_verifier_test.go"],
  embed = [":cert_verifier"],
  embedsrcs = [
    "example_cert_key/client_root_cert.der",
    "example_cert_key/server_root_cert.der",
    "example_cert_key/client_intermediate_cert.der",
    "example_cert_key/server_intermediate_cert.der",
    "example_cert_key/client_leaf_cert.der",
    "example_cert_key/server_leaf_cert.der",

  ],
  deps = [
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "//internal/v2/fakes2av2",
    "@org_golang_google_grpc//:go_default_library",
    "@org_golang_google_grpc//credentials/insecure:go_default_library",
  ],
)
