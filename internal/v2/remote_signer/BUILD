load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)

go_library(
  name = "remote_signer",
  srcs = ["remote_signer.go"],
  importpath = "github.com/google/s2a-go/internal/v2/remote_signer",
)

go_test(
  name = "remote_signer_test",
  srcs = ["remote_signer_test.go"],
  embed = [":remote_signer"],
  embedsrcs = [
    "example_cert_key/cert.pem",
    "example_cert_key/key.pem",
  ],
)
