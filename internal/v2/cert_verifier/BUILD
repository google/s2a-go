load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)


go_library(
  name = "cert_verifier",
  srcs = ["cert_verifier.go"],
  importpath = "github.com/google/s2a-go/internal/v2/cert_verifier",
)

go_test(
  name = "cert_verifier_test",
  srcs = ["cert_verifier_test.go"],
  embed = [":cert_verifier"],
  embedsrcs = [
    "example_cert_key/client_cert.pem",
    "example_cert_key/client_key.pem",
    "example_cert_key/server_cert.pem",
    "example_cert_key/server_key.pem",
  ],
)
