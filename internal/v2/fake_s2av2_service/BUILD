load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
  name = "fake_s2av2_service",
  srcs = ["fake_s2av2_service.go"],
  testonly = True,
  deps = [
    "//internal/v2/fake_s2av2:fake_s2av2",
    "//internal/proto/v2/s2a_go_proto:s2a_go_proto",
    "@org_golang_google_grpc//:go_default_library",
  ],
)
