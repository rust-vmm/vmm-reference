#!/bin/bash

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

set -euo pipefail

if git diff origin/main..HEAD --name-only | grep -q ^resources/ ; then
  ACTION="trigger: vmm-reference-build-resources"
else
  ACTION="command: \"echo No changes in resources\""
fi

echo "
steps:
  - label: 'trigger-build-resources'
    ${ACTION}
"
