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
    "example_cert_key/client_key.pem",
    "example_cert_key/server_key.pem",
  ],
  deps = [
    "//internal/v2/cert_verifier",
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
)
