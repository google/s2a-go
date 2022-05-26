load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)

go_library(
  name = "tls_config_store",
  srcs = ["tls_config_store.go"],
  importpath = "github.com/google/s2a-go/internal/v2/tls_config_store",
  embedsrcs = [
    "example_cert_key/client_cert.pem",
    "example_cert_key/client_key.pem",
    "example_cert_key/server_cert.pem",
    "example_cert_key/server_key.pem",
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
