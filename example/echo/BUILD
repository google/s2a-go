load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
  default_visibility = ["//example:__subpackages__"],
)

go_library(
  name = "echo",
  srcs = ["echo.go"],
  importpath = "github.com/google/s2a-go/example/echo",
  testonly = True,
  deps = ["//example/proto/echo_go_proto:echo_go_proto"],
)
