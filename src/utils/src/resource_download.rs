// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, PartialEq)]
pub enum Error {
    DownloadError(String),
}

/// Downloads from S3 the first resource that match the parameters:
///     - `r_type`: the resource type; e.g. "kernel", "disk".
///     - `r_name`: the resource name; e.g. "bzimage-hello-busybox-halt"
///     - `r_tags`: optional tags to filter the resources; e.g. "{\"halt-after-boot\": true}"
pub fn s3_download(r_type: &str, r_name: &str, r_tags: Option<&str>) -> Result<PathBuf, Error> {
    let dld_script = format!(
        "{}/../../tests/tools/s3_download.py",
        env!("CARGO_MANIFEST_DIR")
    );

    let output = Command::new(dld_script.as_str())
        .arg("-t")
        .arg(r_type)
        .arg("-n")
        .arg(r_name)
        .arg("--tags")
        .arg(r_tags.unwrap_or("{}"))
        .arg("-1")
        .output()
        .expect("failed to execute process");

    if !output.status.success() {
        return Err(Error::DownloadError(
            String::from_utf8(output.stderr).unwrap(),
        ));
    }

    let res: String = String::from_utf8(output.stdout)
        .unwrap()
        .split('\n')
        .map(String::from)
        .nth(0)
        .ok_or(Error::DownloadError(String::from("Not found.")))?;
    Ok(PathBuf::from(res))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_required() {
        assert!(matches!(
            s3_download("", "", None).unwrap_err(),
            Error::DownloadError(e) if e.contains("Missing required parameter")
        ));

        assert!(matches!(
            s3_download("kernel", "", None).unwrap_err(),
            Error::DownloadError(e) if e.contains("Missing required parameter")
        ));

        assert!(matches!(
            s3_download("", "vmlinux-focal", None).unwrap_err(),
            Error::DownloadError(e) if e.contains("Missing required parameter")
        ));
    }

    #[test]
    fn test_resource_not_found() {
        assert!(matches!(
            s3_download("disk", "vmlinux-focal", None).unwrap_err(),
            Error::DownloadError(e) if e.contains("No resources found")
        ));
    }
}
