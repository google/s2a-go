load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)

go_library(
  name = "remote_signer",
  srcs = ["remote_signer.go"],
  importpath = "github.com/google/s2a-go/internal/v2/remote_signer",
  deps = [
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "//internal/proto/common_go_proto:common_go_proto",
  ],
)

go_test(
  name = "remote_signer_test",
  srcs = ["remote_signer_test.go"],
  embed = [":remote_signer"],
  embedsrcs = [
    "example_cert_key/cert.pem",
    "example_cert_key/cert.der",
    "example_cert_key/key.pem",
  ],
  deps = [
    "@org_golang_google_grpc//credentials/insecure:go_default_library",
    "@org_golang_google_grpc//:go_default_library",
    "//internal/v2/fakes2av2",
  ],
)
