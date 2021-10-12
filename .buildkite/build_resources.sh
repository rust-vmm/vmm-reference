#!/bin/bash

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

set -euo pipefail

if git diff origin/main..HEAD --name-only | grep -q ^resources/ ; then
  SKIP="false"
else
  SKIP="\"No changes in resources\""
fi

echo "
steps:
  - label: 'trigger-build-resources'
    trigger: vmm-reference-build-resources
    skip: ${SKIP}
"
