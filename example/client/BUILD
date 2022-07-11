load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
  name = "client",
  srcs = ["client.go"],
  testonly = True,
  deps = [
    "//internal/proto/common_go_proto:common_go_proto",
    "//example/proto/echo_go_proto:echo_go_proto",
    "//internal/v2:v2",
    "@org_golang_google_grpc//:go_default_library",
  ],
)
