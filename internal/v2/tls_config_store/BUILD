load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)

# TODO(rmehta19) : Investigate how to use embedsrcs with data in a top level directory. If possible, move example_cert_key under s2a-go/internal/v2

go_library(
  name = "tls_config_store",
  srcs = ["tls_config_store.go"],
  importpath = "github.com/google/s2a-go/internal/v2/tls_config_store",
  embedsrcs = [
    "example_cert_key/client_cert.pem",
    "example_cert_key/server_cert.pem",
    "example_cert_key/client_key.pem",
    "example_cert_key/server_key.pem",
  ],
  deps = [
    "//internal/v2/cert_verifier",
    "//internal/proto/v2/common_go_proto:common_go_proto",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "@org_golang_google_grpc//:go_default_library",
    "@org_golang_google_grpc//credentials/insecure:go_default_library",
  ],
)

go_test(
  name = "tls_config_store_test",
  srcs = ["tls_config_store_test.go"],
  embed = [":tls_config_store"],
  embedsrcs = [
    "example_cert_key/client_cert.pem",
    "example_cert_key/client_key.pem",
    "example_cert_key/server_cert.pem",
    "example_cert_key/server_key.pem",
  ],
  deps = [
    "//internal/v2/fakes2av2",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "@org_golang_google_grpc//:go_default_library",
  ],
)
