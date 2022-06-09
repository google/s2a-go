load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
  name = "fakes2av2_server",
  srcs = ["fakes2av2_server.go"],
  testonly = True,
  deps = [
    "//internal/v2/fakes2av2:fakes2av2",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "@org_golang_google_grpc//:go_default_library",
  ],
)
