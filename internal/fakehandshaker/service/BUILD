# Copyright 2021 Google LLC
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

# Description:
#  Utility for calling the S2A.

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

licenses(["notice"])

package(
    default_visibility = ["//:__subpackages__"],
)

go_library(
    name = "service",
    srcs = ["s2a_service.go"],
    importpath = "github.com/google/s2a-go/internal/fakehandshaker/service",
    deps = [
        "//internal/proto/common_go_proto:common_go_proto",
        "//internal/proto/s2a_go_proto:s2a_go_proto",
        "@org_golang_google_grpc//codes:go_default_library",
    ],
)

go_test(
    name = "service_test",
    size = "small",
    srcs = ["s2a_service_test.go"],
    embed = [":service"],
    deps = [
        "//internal/proto/common_go_proto:common_go_proto",
        "//internal/proto/s2a_go_proto:s2a_go_proto",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    ],
)
