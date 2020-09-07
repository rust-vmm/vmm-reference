// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

//! CLI for the Reference VMM.

#![deny(missing_docs)]

extern crate clap;
extern crate vmm;

use std::convert::TryFrom;
use std::result;

use clap::{App, Arg};
use vmm::{KernelConfig, MemoryConfig, VMMConfig, VcpuConfig};

/// Command line parser.
pub struct CLI;

impl CLI {
    /// Parses the command line options into VMM configurations.
    ///
    /// # Arguments
    ///
    /// * `app_name` - name of the running program.
    pub fn new(app_name: String) -> result::Result<VMMConfig, String> {
        let matches = App::new(app_name)
            .arg(
                Arg::with_name("memory")
                    .long("memory")
                    .required(true)
                    .takes_value(true)
                    .validator(Self::validate_memory_config),
            )
            .arg(
                Arg::with_name("vcpus")
                    .long("vcpus")
                    .required(true)
                    .takes_value(true)
                    .validator(Self::validate_vcpu_config),
            )
            .arg(
                Arg::with_name("kernel")
                    .long("kernel")
                    .required(true)
                    .takes_value(true)
                    .validator(Self::validate_kernel_config),
            )
            .get_matches();

        Ok(VMMConfig {
            memory_config: MemoryConfig::try_from(
                matches
                    .value_of("memory")
                    .expect("Missing memory configuration")
                    .to_string(),
            )
            .map_err(|e| format!("{:?}", e))?,
            kernel_config: KernelConfig::try_from(
                matches
                    .value_of("kernel")
                    .expect("Missing kernel configuration")
                    .to_string(),
            )
            .map_err(|e| format!("{:?}", e))?,
            vcpu_config: VcpuConfig::try_from(
                matches
                    .value_of("vcpus")
                    .expect("Missing vCPU configuration")
                    .to_string(),
            )
            .map_err(|e| format!("{:?}", e))?,
        })
    }

    fn validate_memory_config(mem_config_str: String) -> result::Result<(), String> {
        MemoryConfig::try_from(mem_config_str)
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }

    fn validate_vcpu_config(vcpu_config_str: String) -> result::Result<(), String> {
        VcpuConfig::try_from(vcpu_config_str)
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }

    fn validate_kernel_config(kernel_config_str: String) -> result::Result<(), String> {
        KernelConfig::try_from(kernel_config_str)
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }
}
