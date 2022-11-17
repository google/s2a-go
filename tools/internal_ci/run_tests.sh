# Copyright 2021 Google LLC
#
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

#!/bin/bash

# Fail on any error.
set -e

# Display commands being run.
set -x

fail_with_debug_output() {
  ls -l
  df -h /
  exit 1
}

run_tests() {
  time bazel test --features=-debug_prefix_map_pwd_is_dot -- ... || fail_with_debug_output
}

main() {
  if [[ -n "${KOKORO_ROOT}" ]]; then
    chmod +x "${KOKORO_GFILE_DIR}/use_bazel.sh"
    "${KOKORO_GFILE_DIR}/use_bazel.sh" 4.2.1
  fi
  run_tests
}

main "$@"
