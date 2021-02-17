#!/usr/bin/python3
# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Script for downloading the resources required for tests.
It returns the absolute path of the downloaded resource to stdout."""

import json
from optparse import OptionParser
import os
import pathlib

from utils import S3ResourceFetcher


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-t", "--resource-type", dest="resource_type",
                      help="Type of resource to download.")
    parser.add_option("-n", "--resource-name",
                      dest="resource_name",
                      help="Name of resource to download.")
    parser.add_option("--tags",
                      dest="tags",
                      help="The optional tags that the resource must have as a dictionary.",
                      default="{}")
    parser.add_option("-p", "--path",
                      dest="path",
                      help="The directory where to save the downloaded resource. "
                           "This path represents the root used when creating the "
                           "structure. The full path is created by joining this path "
                           "and the relative_path defined in the resource manifest.")
    parser.add_option("-1",
                      dest="first",
                      default=False,
                      action="store_true",
                      help="Download the first resource that matches the parameters.")

    (options, args) = parser.parse_args()

    required_ops = ["resource_type", "resource_name"]
    for r in required_ops:
        if not getattr(options, r):
            parser.error("Missing required parameter: %s" % r)

    resource_tags = options.tags
    if resource_tags is not {}:
        resource_tags = json.loads(resource_tags)

    s3_resource_fetcher = S3ResourceFetcher(
        "vmm-reference-test-resources",
        os.path.join(
            pathlib.Path(__file__).parent.absolute(),
            "resource_manifest.json"
        ))

    res = s3_resource_fetcher.download(
        resource_type=options.resource_type,
        resource_name=options.resource_name,
        tags=resource_tags,
        download_location=options.path,
        first=options.first
    )

    # When there is a single resource, this is not returned in an array.
    # Create an array with a single element in this case.
    res = [res] if options.first is True else res
    for resource in res:
        print(resource)
