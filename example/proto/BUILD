# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_grpc_library")

package(
  default_visibility = ["//example:__subpackages__"],
)

proto_library(
  name = "echo_proto",
  srcs = ["echo.proto"],
)

# Generates Go code of proto messages.
go_proto_library(
  name = "echo_go_proto",
  importpath = "github.com/google/s2a-go/example/proto/echo_go_proto",
  protos = [":echo_proto"],
)

# Generates gRPC services.
go_grpc_library(
  name = "echo_go_grpc_proto",
  importpath = "github.com/google/s2a-go/example/proto/echo_go_grpc_proto",
  protos = [":echo_proto"],
)
