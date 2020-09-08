// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::convert::TryFrom;
use std::fmt;
use std::path::PathBuf;
use std::result;

/// Errors encountered converting the `*Config` objects.
pub enum ConversionError {
    /// Failed to parse the string representation for the kernel.
    ParseKernel(String),
    /// Failed to parse the string representation for guest memory.
    ParseMemory(String),
    /// Failed to parse the string representation for the vCPUs.
    ParseVcpus(String),
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConversionError::*;
        match self {
            ParseKernel(ref s) => write!(f, "Invalid input for kernel: {}", s),
            ParseMemory(ref s) => write!(f, "Invalid input for memory: {}", s),
            ParseVcpus(ref s) => write!(f, "Invalid input for vCPUs: {}", s),
        }
    }
}

/// Guest memory configurations.
#[derive(Debug, Default, PartialEq)]
pub struct MemoryConfig {
    /// Guest memory size in MiB.
    pub mem_size_mib: u32,
}

impl TryFrom<String> for MemoryConfig {
    type Error = ConversionError;

    fn try_from(mem_cfg_str: String) -> result::Result<Self, Self::Error> {
        // Supported options: `size=<u32>`
        let mem_cfg_str_lower = mem_cfg_str.to_lowercase();
        let tokens: Vec<&str> = mem_cfg_str_lower
            .split('=')
            .filter(|tok| !tok.is_empty())
            .collect();
        if tokens.len() != 2 {
            return Err(ConversionError::ParseMemory(mem_cfg_str));
        }
        if tokens[0] != "mem_size_mib" {
            return Err(ConversionError::ParseMemory(tokens[0].to_string()));
        }
        tokens[1]
            .parse::<u32>()
            .and_then(|mem_size_mib| Ok(MemoryConfig { mem_size_mib }))
            .map_err(|_| ConversionError::ParseMemory(tokens[1].to_string()))
    }
}

/// vCPU configurations.
#[derive(Debug, Default, PartialEq)]
pub struct VcpuConfig {
    /// Number of vCPUs.
    pub num_vcpus: u8,
}

impl TryFrom<String> for VcpuConfig {
    type Error = ConversionError;

    fn try_from(vcpu_cfg_str: String) -> result::Result<Self, Self::Error> {
        // Supported options: `num_vcpus=<u8>`
        let vcpu_cfg_str_lower = vcpu_cfg_str.to_lowercase();
        let tokens: Vec<&str> = vcpu_cfg_str_lower
            .split('=')
            .filter(|tok| !tok.is_empty())
            .collect();
        if tokens.len() != 2 {
            return Err(ConversionError::ParseVcpus(vcpu_cfg_str));
        }
        if tokens[0] != "num_vcpus" {
            return Err(ConversionError::ParseVcpus(tokens[0].to_string()));
        }
        tokens[1]
            .parse::<u8>()
            .and_then(|num_vcpus| Ok(VcpuConfig { num_vcpus }))
            .map_err(|_| ConversionError::ParseVcpus(tokens[1].to_string()))
    }
}

/// Guest kernel configurations.
#[derive(Debug, Default, PartialEq)]
pub struct KernelConfig {
    /// Kernel command line.
    pub cmdline: String,
    /// Path to the kernel image.
    pub path: PathBuf,
    /// Start address for high memory.
    pub himem_start: u64,
}

impl TryFrom<String> for KernelConfig {
    type Error = ConversionError;

    fn try_from(kernel_cfg_str: String) -> result::Result<Self, Self::Error> {
        // Supported options:
        // `cmdline=<"string">,path=/path/to/kernel,himem_start=<u64>`
        // Required: all
        let options: Vec<&str> = kernel_cfg_str.split(',').collect();
        if options.len() != 3 {
            return Err(ConversionError::ParseKernel(kernel_cfg_str));
        }

        let mut cmdline: Option<String> = None;
        let mut path: Option<PathBuf> = None;
        let mut himem_start: Option<u64> = None;

        for opt in options {
            let tokens: Vec<&str> = opt.split('=').filter(|tok| !tok.is_empty()).collect();
            match tokens[0] {
                "cmdline" => cmdline = Some(tokens[1..].join("=")),
                "path" => {
                    if tokens.len() != 2 {
                        return Err(ConversionError::ParseKernel(opt.to_string()));
                    }
                    path = Some(PathBuf::from(tokens[1]));
                }
                "himem_start" => {
                    if tokens.len() != 2 {
                        return Err(ConversionError::ParseKernel(opt.to_string()));
                    }
                    himem_start = Some(
                        tokens[1]
                            .parse::<u64>()
                            .map_err(|_| ConversionError::ParseKernel(tokens[1].to_string()))?,
                    );
                }
                _ => return Err(ConversionError::ParseKernel(kernel_cfg_str.to_string())),
            }
        }

        Ok(KernelConfig {
            cmdline: cmdline
                .ok_or_else(|| ConversionError::ParseKernel(kernel_cfg_str.to_string()))?,
            path: path.ok_or_else(|| ConversionError::ParseKernel(kernel_cfg_str.to_string()))?,
            himem_start: himem_start
                .ok_or_else(|| ConversionError::ParseKernel(kernel_cfg_str.to_string()))?,
        })
    }
}

/// VMM configuration.
#[derive(Debug, Default, PartialEq)]
pub struct VMMConfig {
    /// Guest memory configuration.
    pub memory_config: MemoryConfig,
    /// vCPU configuration.
    pub vcpu_config: VcpuConfig,
    /// Guest kernel configuration.
    pub kernel_config: KernelConfig,
}
