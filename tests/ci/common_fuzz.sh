# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source tests/ci/common_posix_setup.sh

if [ -v CODEBUILD_FUZZING_ROOT ]; then
  CORPUS_ROOT="${CODEBUILD_FUZZING_ROOT}/fuzzing"
else
  CORPUS_ROOT="${BUILD_ROOT}/mock_efs/fuzzing"
fi
echo "$CORPUS_ROOT"

if [ -v CODEBUILD_BUILD_ID ]; then
  BUILD_ID=$CODEBUILD_BUILD_ID
else
  # Generate a random string in bash https://unix.stackexchange.com/questions/230673/how-to-generate-a-random-string
  BUILD_ID=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')
fi
echo "$BUILD_ID"

function put_metric_count {
  put_metric --unit Count "$@"
}

function put_metric {
  # This call to publish the metric could fail but we don't want to fail the build +e turns off exit on error
  set +e
  aws cloudwatch put-metric-data \
    --namespace AWS-LC-Fuzz \
    "$@" || echo "Publishing metric failed, continuing with the rest of the build"
  # Turn it back on for the rest of the build
  set -e
}
