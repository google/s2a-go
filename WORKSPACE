workspace(name = "s2a_go")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Bazel's proto rules.
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
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "69de5c704a05ff37862f7e0f5534d4f479418afc21806c887db544a316f3cb6b",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
go_rules_dependencies()
go_register_toolchains(version = "1.16")

# Bazel Gazelle.
http_archive(
    name = "bazel_gazelle",
    sha256 = "62ca106be173579c0a167deb23358fdfe71ffa1e4cfdddf5582af26520f1c66f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
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
# Last updated: September 7, 2021.
go_repository(
  name = "org_golang_google_protobuf",
  importpath = "google.golang/org/protobuf",
  version = "v1.27.1",
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
