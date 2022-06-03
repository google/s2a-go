# Description: gRPC transport credentials that use S2Av2
load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)

go_library(
  name = "s2av2",
  srcs = [
    "s2av2.go",
  ],
  importpath = "github.com/google/s2a-go/internal/v2/s2av2",
  deps = [
    "//internal/v2/tls_config_store",
    "@org_golang_google_grpc//credentials:go_default_library",
    "@org_golang_google_grpc//:go_default_library",
  ]
)

go_test(
  name = "s2av2_test",
  srcs = [
    "s2av2_test.go",
  ],
  embed = [":s2av2"],
  deps = [
    "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    "@com_github_google_go_cmp//cmp:go_default_library",
  ],
)
