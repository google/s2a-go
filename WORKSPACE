workspace(name = "s2a_go")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Bazel's proto rules.
#
# Last updated: April 8, 2022.
http_archive(
    name = "rules_proto",
    sha256 = "e017528fd1c91c5a33f15493e3a398181a9e821a804eb7ff5acdd1d2d6c2b18d",
    strip_prefix = "rules_proto-4.0.0-3.20.0",
    urls = [
        "https://github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0-3.20.0.tar.gz",
    ],
)
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
rules_proto_dependencies()
rules_proto_toolchains()

# Bazel's Go rules.
#
# Last updated: April 8, 2022.
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "f2dcd210c7095febe54b804bb1cd3a58fe8435a909db2ec04e31542631cf715c",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
go_rules_dependencies()
go_register_toolchains(version = "1.16")

# Bazel Gazelle.
#
# Last updated: April 8, 2022.
http_archive(
    name = "bazel_gazelle",
    sha256 = "5982e5463f171da99e3bdaeff8c0f48283a7a5f396ec5282910b9e8a49c0dd7e",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.25.0/bazel-gazelle-v0.25.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.25.0/bazel-gazelle-v0.25.0.tar.gz",
    ],
)
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
gazelle_dependencies()

# gRPC-Go.
go_repository(
  name = "org_golang_google_grpc",
  importpath = "google.golang.org/grpc",
  sum = "h1:/9BgsAsa5nWe26HqOlvlgJnqBuktYOLCgjCPqsa56W0=",
  version = "v1.38.0",
)

# Go Protobuf.
#
# Last updated: April 8, 2022.
go_repository(
  name = "org_golang_google_protobuf",
  importpath = "google.golang/org/protobuf",
  version = "v1.28.0",
)

# Go Cryptography. No stable versions available.
#
# Last updated: June 4,2021.
go_repository(
  name = "org_golang_x_crypto",
  importpath = "golang.org/x/crypto",
  commit = "c07d793c2f9aacf728fe68cbd7acd73adbd04159"
)

# Go Sync. No stable versions available.
#
# Last updated: June 4,2021.
go_repository(
  name = "org_golang_x_sync",
  importpath = "golang.org/x/sync",
  commit = "036812b2e83c0ddf193dd5a34e034151da389d09"
)

# Go Cmp. No stable versions available.
#
# Last updated: June 4,2021.
go_repository(
  name = "com_github_google_go_cmp",
  importpath = "github.com/google/go-cmp",
  commit = "290a6a23966f9edffe2a0a4a1d8dd065cc0753fd"
)

# Go Sys. No stable versions available.
#
# Last updated: April 8, 2022.
go_repository(
  name = "org_golang_x_sys",
  importpath = "golang.org/x/sys",
)
