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

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "client",
    testonly = True,
    srcs = ["client.go"],
    deps = [
        "//:s2a",
        "//example/proto/echo_go_proto",
        "//internal/proto/common_go_proto",
        "//internal/proto/v2/s2a_go_proto",
        "@org_golang_google_grpc//:go_default_library",
    ],
)
