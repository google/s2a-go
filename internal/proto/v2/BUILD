# Copyright 2022 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Description:
#   This BUILD file contains v2 proto targets for the S2A client libraries.

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_grpc_library")

package(default_visibility = ["//:__subpackages__"])

licenses(["notice"])

proto_library(
    name = "common_proto",
    srcs = ["common.proto"],
)

proto_library(
    name = "s2a_context_proto",
    srcs = ["s2a_context.proto"],
    deps = [":common_proto"],
)

proto_library(
    name = "s2a_proto",
    srcs = ["s2a.proto"],
    deps = [
      ":common_proto",
      ":s2a_context_proto",
      "//internal/proto:common_proto",
    ],
)

go_proto_library(
    name = "common_go_proto",
    importpath = "github.com/google/s2a-go/internal/proto/v2/common_go_proto",
    protos = [":common_proto"],
)

go_proto_library(
    name = "s2a_context_go_proto",
    importpath = "github.com/google/s2a-go/internal/proto/v2/s2a_context_go_proto",
    protos = [":s2a_context_proto"],
    deps = [
      ":common_go_proto",
      "//internal/proto:common_go_proto",
    ],
)

go_proto_library(
    name = "s2a_go_proto",
    importpath = "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto",
    protos = [":s2a_proto"],
    deps = [
      ":common_go_proto",
      ":s2a_context_go_proto",
      "//internal/proto:common_go_proto",
    ],
)

go_grpc_library(
    name = "s2a_go_grpc_proto",
    importpath = "github.com/google/s2a-go/internal/proto/v2/s2a_go_grpc_proto",
    protos = [":s2a_proto"],
    deps = [
      ":common_go_proto",
      ":s2a_context_go_proto",
      "//internal/proto:common_go_proto",
    ],
)

