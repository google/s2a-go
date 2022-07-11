load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
  name = "server",
  srcs = ["server.go"],
  testonly = True,
  deps = [
    "//example/echo:echo",
    "//internal/proto/common_go_proto:common_go_proto",
    "//internal/v2:v2",
    "//example/proto/echo_go_proto:echo_go_proto",
    "@org_golang_google_grpc//:go_default_library",
  ],
)
