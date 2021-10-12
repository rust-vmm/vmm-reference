#!/bin/bash

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

set -e

SKIP="\"No changes in resources or unknown Pull Request\""
if [ "${BUILDKITE_PULL_REQUEST}" ] ; then
  URL="https://api.github.com/repos/rust-vmm/vmm-reference/pulls/${BUILDKITE_PULL_REQUEST}/files"
  # if curl -s $URL | jq -r '.[] | .filename' | grep -q ^resources/; then
  if curl -s $URL | python3 -c 'import json,sys;[print(v["filename"]) for v in json.load(sys.stdin)]' | grep -q ^resources/ ; then
    SKIP="false"
  fi
fi

echo "
steps:
  - label: 'trigger-build-resources'
    trigger: vmm-reference-build-resources
    skip: ${SKIP}
"
