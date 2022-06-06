load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
  name = "client",
  srcs = ["client.go"],
  testonly = True,
  deps = [
    "//internal/v2:v2",
    "//example/proto/echo_go_proto:echo_go_proto",
    "@org_golang_google_grpc//:go_default_library",
  ],
)
