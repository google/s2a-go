load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
  default_visibility = ["//internal/v2:__subpackages__"],
)

go_library(
  name = "fake_s2av2",
  srcs = ["fake_s2av2.go"],
  importpath = "github.com/google/s2a-go/internal/v2/fake_s2av2",
  deps = [
    "//internal/proto/v2/common_go_proto:common_go_proto",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
  ],
)
