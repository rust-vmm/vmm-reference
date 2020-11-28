// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

//! CLI for the Reference VMM.

#![deny(missing_docs)]
use std::convert::TryFrom;
use std::result;

use clap::{App, Arg};
use vmm::{BlockConfig, KernelConfig, MemoryConfig, NetConfig, VMMConfig, VcpuConfig};

/// Command line parser.
pub struct CLI;

impl CLI {
    /// Parses the command line options into VMM configurations.
    ///
    /// # Arguments
    ///
    /// * `cmdline_args` - command line arguments passed to the application.
    pub fn launch(cmdline_args: Vec<&str>) -> result::Result<VMMConfig, String> {
        let mut app = App::new(cmdline_args[0].to_string())
            .arg(
                Arg::with_name("memory")
                    .long("memory")
                    .required(true)
                    .takes_value(true)
                    .default_value("size_mib=256")
                    .help("Guest memory configuration.\n\tFormat: \"size_mib=<u32>\""),
            )
            .arg(
                Arg::with_name("vcpu")
                    .long("vcpu")
                    .required(true)
                    .takes_value(true)
                    .default_value("num=1")
                    .help("vCPU configuration.\n\tFormat: \"num=<u8>\""),
            )
            .arg(
                Arg::with_name("kernel")
                    .long("kernel")
                    .required(true)
                    .takes_value(true)
                    .help("Kernel configuration.\n\tFormat: \"path=<string>[,cmdline=<string>,himem_start=<u64>]\""),
            )
            .arg(
                Arg::with_name("net")
                    .long("net")
                    .takes_value(true)
                    .help("Network device configuration. \n\tFormat: \"tap=<string>\"")
            )
            .arg(
                Arg::with_name("block")
                    .long("block")
                    .required(false)
                    .takes_value(true)
                    .help("Block device configuration. \n\tFormat: \"path=<string>\"")
            );

        // Save the usage beforehand as a string, because `get_matches` consumes the `App`.
        let mut help_msg_buf: Vec<u8> = vec![];
        // If the write fails, we'll just have an empty help message.
        let _ = app.write_long_help(&mut help_msg_buf);
        let help_msg = String::from_utf8_lossy(&help_msg_buf);

        let matches = app.get_matches_from_safe(cmdline_args).map_err(|e| {
            eprintln!("{}", help_msg);
            format!("Invalid command line arguments: {}", e)
        })?;

        Ok(VMMConfig {
            memory_config: MemoryConfig::try_from(
                matches
                    .value_of("memory")
                    .expect("Missing memory configuration")
                    .to_string(),
            )
            .map_err(|e| {
                eprintln!("{}", help_msg);
                format!("{}", e)
            })?,
            kernel_config: KernelConfig::try_from(
                matches
                    .value_of("kernel")
                    .expect("Missing kernel configuration")
                    .to_string(),
            )
            .map_err(|e| {
                eprintln!("{}", help_msg);
                format!("{}", e)
            })?,
            vcpu_config: VcpuConfig::try_from(
                matches
                    .value_of("vcpu")
                    .expect("Missing vCPU configuration")
                    .to_string(),
            )
            .map_err(|e| {
                eprintln!("{}", help_msg);
                format!("{}", e)
            })?,
            block_config: match matches.value_of("block") {
                Some(value) => Some(BlockConfig::try_from(value.to_string()).map_err(|e| {
                    eprintln!("{}", help_msg);
                    format!("{}", e)
                })?),
                None => None,
            },
            network_config: match matches.value_of("net") {
                Some(value) => Some(NetConfig::try_from(value.to_string()).map_err(|e| {
                    eprintln!("{}", help_msg);
                    format!("{}", e)
                })?),
                None => None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use vmm::DEFAULT_KERNEL_CMDLINE;

    #[test]
    fn test_launch() {
        // Missing command line arguments.
        assert!(CLI::launch(vec!["foobar"]).is_err());

        // Invalid extra command line parameter.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=128",
            "--vcpu",
            "num=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42",
            "foobar",
        ])
        .is_err());

        // Invalid memory config: invalid value for `size_mib`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=foobar",
            "--vcpu",
            "num=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42",
        ])
        .is_err());

        // Invalid memory config: missing value for `size_mib`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=",
            "--vcpu",
            "num=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42",
        ])
        .is_err());

        // Invalid memory config: unexpected parameter `foobar`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "foobar=1024",
            "--vcpu",
            "num=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42",
        ])
        .is_err());

        // Invalid kernel config: invalid value for `himem_start`.
        // TODO: harden cmdline check.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=128",
            "--vcpu",
            "num=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=foobar",
        ])
        .is_err());

        // Invalid kernel config: missing value for `himem_start`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=128",
            "--vcpu",
            "num=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=",
        ])
        .is_err());

        // Invalid kernel config: unexpected parameter `foobar`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=128",
            "--vcpu",
            "num=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42,foobar=42",
        ])
        .is_err());

        // Invalid vCPU config: invalid value for `num_vcpus`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=128",
            "--vcpu",
            "num=foobar",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42",
        ])
        .is_err());

        // Invalid vCPU config: missing value for `num_vcpus`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=128",
            "--vcpu",
            "num=",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42",
        ])
        .is_err());

        // Invalid vCPU config: unexpected parameter `foobar`.
        assert!(CLI::launch(vec![
            "foobar",
            "--memory",
            "size_mib=128",
            "--vcpu",
            "foobar=1",
            "--kernel",
            "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42",
        ])
        .is_err());

        // OK.
        assert_eq!(
            CLI::launch(vec![
                "foobar",
                "--memory",
                "size_mib=128",
                "--vcpu",
                "num=1",
                "--kernel",
                "path=/foo/bar,cmdline=\"foo=bar bar=foo\",himem_start=42",
            ])
            .unwrap(),
            VMMConfig {
                kernel_config: KernelConfig {
                    path: PathBuf::from("/foo/bar"),
                    cmdline: "\"foo=bar bar=foo\"".to_string(),
                    himem_start: 42,
                },
                memory_config: MemoryConfig { size_mib: 128 },
                vcpu_config: VcpuConfig { num: 1 },
                block_config: None,
                network_config: None,
            }
        );

        // Test default values.
        assert_eq!(
            CLI::launch(vec!["foobar", "--kernel", "path=/foo/bar",]).unwrap(),
            VMMConfig {
                kernel_config: KernelConfig {
                    path: PathBuf::from("/foo/bar"),
                    cmdline: DEFAULT_KERNEL_CMDLINE.to_string(),
                    himem_start: 1048576,
                },
                memory_config: MemoryConfig { size_mib: 256 },
                vcpu_config: VcpuConfig { num: 1 },
                block_config: None,
                network_config: None,
            }
        );
    }
}
