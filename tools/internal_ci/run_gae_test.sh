# Copyright 2024 Google LLC
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

# inspired by https://github.com/grpc/grpc-java/blob/master/buildscripts/kokoro/gae-interop.sh

# Fail on any error.
set -e

# Display commands being run.
set -x

KOKORO_GAE_DEFAULT_APP_VERSION="default"
PROJECT_ID=$(curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google")

# Setup app.
cd "tools/internal_ci/test_gae"
go mod edit -go=1.22
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

# Deploy the app.
gcloud app deploy --version=$KOKORO_GAE_DEFAULT_APP_VERSION
APP_URL=$(gcloud app browse --no-launch-browser --version="$KOKORO_GAE_DEFAULT_APP_VERSION" --project="$PROJECT_ID")

if curl -s $APP_URL | grep "success"
then
    exit 0
else
    exit 1
fi
