// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::convert::TryFrom;
use std::fmt;
use std::path::PathBuf;
use std::result;

use super::{DEFAULT_HIGH_RAM_START, DEFAULT_KERNEL_CMDLINE};

/// Errors encountered converting the `*Config` objects.
#[derive(Debug, PartialEq)]
pub enum ConversionError {
    /// Failed to parse the string representation for the kernel.
    ParseKernel(String),
    /// Failed to parse the string representation for guest memory.
    ParseMemory(String),
    /// Failed to parse the string representation for the vCPUs.
    ParseVcpus(String),
    /// Failed to parse the string representation for the network.
    ParseNetwork(String),
    /// Failed to parse the string representation for the block.
    ParseBlock(String),
    /// Failed to parse the string representation for the vsock.
    ParseVsock(String),
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConversionError::*;
        match self {
            ParseKernel(ref s) => write!(f, "Invalid input for kernel: {}", s),
            ParseMemory(ref s) => write!(f, "Invalid input for memory: {}", s),
            ParseVcpus(ref s) => write!(f, "Invalid input for vCPUs: {}", s),
            ParseNetwork(ref s) => write!(f, "Invalid input for network: {}", s),
            ParseBlock(ref s) => write!(f, "Invalid input for block: {}", s),
            ParseVsock(ref s) => write!(f, "Invalid input for vsock: {}", s),
        }
    }
}

/// Guest memory configurations.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemoryConfig {
    /// Guest memory size in MiB.
    pub size_mib: u32,
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
        if tokens[0] != "size_mib" {
            return Err(ConversionError::ParseMemory(tokens[0].to_string()));
        }
        tokens[1]
            .parse::<u32>()
            .map(|mem_size_mib| MemoryConfig {
                size_mib: mem_size_mib,
            })
            .map_err(|_| ConversionError::ParseMemory(tokens[1].to_string()))
    }
}

/// vCPU configurations.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VcpuConfig {
    /// Number of vCPUs.
    pub num: u8,
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
        if tokens[0] != "num" {
            return Err(ConversionError::ParseVcpus(tokens[0].to_string()));
        }
        let vcpu_config = tokens[1]
            .parse::<u8>()
            .map(|num_vcpus| VcpuConfig { num: num_vcpus })
            .map_err(|_| ConversionError::ParseVcpus(tokens[1].to_string()))?;
        if vcpu_config.num == 0 {
            return Err(ConversionError::ParseVcpus(tokens[1].to_string()));
        }
        Ok(vcpu_config)
    }
}

/// Guest kernel configurations.
#[derive(Clone, Debug, Default, PartialEq)]
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
        // Required: path
        let options: Vec<&str> = kernel_cfg_str
            .split(',')
            .filter(|tok| !tok.is_empty())
            .collect();

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
            cmdline: cmdline.unwrap_or_else(|| DEFAULT_KERNEL_CMDLINE.to_string()),
            path: path.ok_or_else(|| ConversionError::ParseKernel(kernel_cfg_str.to_string()))?,
            himem_start: himem_start.unwrap_or(DEFAULT_HIGH_RAM_START),
        })
    }
}
/// Network device configuration.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetConfig {
    /// Name of tap device.
    pub tap_name: String,
}

impl TryFrom<String> for NetConfig {
    type Error = ConversionError;

    fn try_from(net_config_str: String) -> Result<Self, Self::Error> {
        // Supported options: `tap=String`
        let tokens: Vec<&str> = net_config_str
            .split('=')
            .filter(|tok| !tok.is_empty())
            .collect();
        if tokens.len() != 2 {
            return Err(ConversionError::ParseNetwork(net_config_str));
        }
        if tokens[0] != "tap" {
            return Err(ConversionError::ParseNetwork(tokens[0].to_string()));
        }

        Ok(Self {
            tap_name: String::from(tokens[1]),
        })
    }
}

/// Block device configuration.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BlockConfig {
    /// Path to the block device backend.
    pub path: PathBuf,
}

impl TryFrom<String> for BlockConfig {
    type Error = ConversionError;

    fn try_from(block_cfg_str: String) -> Result<Self, Self::Error> {
        // Supported options: `path=PathBuf`
        let tokens: Vec<&str> = block_cfg_str
            .split('=')
            .filter(|tok| !tok.is_empty())
            .collect();
        if tokens.len() != 2 {
            return Err(ConversionError::ParseBlock(block_cfg_str));
        }
        if tokens[0] != "path" {
            return Err(ConversionError::ParseBlock(tokens[0].to_string()));
        }

        Ok(Self {
            path: PathBuf::from(tokens[1]),
        })
    }
}

/// Vsock device configuration.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VsockConfig {
    /// Guest cid value.
    pub cid: u32,
    /// Path to the Unix domain socket on the host.
    pub uds_path: PathBuf,
}

impl TryFrom<String> for VsockConfig {
    type Error = ConversionError;

    fn try_from(str: String) -> result::Result<Self, Self::Error> {
        // Supported options:
        // `cid=<u32>,uds_path=/path/to/uds`
        // Required: cid, path
        let options: Vec<&str> = str.split(',').filter(|tok| !tok.is_empty()).collect();

        let mut cid: Option<u32> = None;
        let mut uds_path: Option<PathBuf> = None;

        for opt in options {
            let tokens: Vec<&str> = opt.split('=').filter(|tok| !tok.is_empty()).collect();
            match tokens[0] {
                "cid" => {
                    if tokens.len() != 2 {
                        return Err(ConversionError::ParseVsock(opt.to_string()));
                    }
                    cid = Some(
                        tokens[1]
                            .parse::<u32>()
                            .map_err(|_| ConversionError::ParseVsock(tokens[1].to_string()))?,
                    );
                }
                "uds_path" => {
                    if tokens.len() != 2 {
                        return Err(ConversionError::ParseKernel(opt.to_string()));
                    }
                    uds_path = Some(PathBuf::from(tokens[1]));
                }
                _ => return Err(ConversionError::ParseVsock(str.to_string())),
            }
        }

        Ok(VsockConfig {
            cid: cid.ok_or_else(|| ConversionError::ParseVsock(str.to_string()))?,
            uds_path: uds_path.ok_or_else(|| ConversionError::ParseVsock(str.to_string()))?,
        })
    }
}

/// VMM configuration.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VMMConfig {
    /// Guest memory configuration.
    pub memory_config: MemoryConfig,
    /// vCPU configuration.
    pub vcpu_config: VcpuConfig,
    /// Guest kernel configuration.
    pub kernel_config: KernelConfig,
    /// Network device configuration.
    pub network_config: Option<NetConfig>,
    /// Block device configuration.
    pub block_config: Option<BlockConfig>,
    /// Vsock device configuration.
    pub vsock_config: Option<VsockConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_config() {
        // Check that additional commas in the kernel string do not cause a panic.
        let kernel_str = "path=/foo/bar,cmdline=\"foo=bar\",himem_start=42,";
        let expected_kernel_config = KernelConfig {
            cmdline: "\"foo=bar\"".to_string(),
            himem_start: 42,
            path: PathBuf::from("/foo/bar"),
        };
        assert_eq!(
            KernelConfig::try_from(kernel_str.to_string()).unwrap(),
            expected_kernel_config
        );

        // Check that an empty path returns a conversion error.
        let kernel_str = "path=,cmdline=\"foo=bar\",himem_start=42,";
        let expected_error = ConversionError::ParseKernel("path=".to_string());
        assert_eq!(
            KernelConfig::try_from(kernel_str.to_string()).unwrap_err(),
            expected_error
        );
    }

    #[test]
    fn test_vcpu_config() {
        // Invalid vCPU numbers: 0, 256 (exceeds the u8 limit).
        let vcpu_str = "num=0";
        assert_eq!(
            VcpuConfig::try_from(vcpu_str.to_string()).unwrap_err(),
            ConversionError::ParseVcpus("0".to_string())
        );

        let vcpu_str = "num=256";
        assert_eq!(
            VcpuConfig::try_from(vcpu_str.to_string()).unwrap_err(),
            ConversionError::ParseVcpus("256".to_string())
        );

        // Missing vCPU number in config string.
        let vcpu_str = "num=";
        assert_eq!(
            VcpuConfig::try_from(vcpu_str.to_string()).unwrap_err(),
            ConversionError::ParseVcpus("num=".to_string())
        );
    }

    #[test]
    fn test_network_config() {
        let network_str = "tap=vmtap".to_string();
        let network_cfg = NetConfig::try_from(network_str).unwrap();
        let expected_cfg = NetConfig {
            tap_name: "vmtap".to_string(),
        };
        assert_eq!(network_cfg, expected_cfg);

        // Test case: empty string error.
        assert!(NetConfig::try_from(String::new()).is_err());

        // Test case: empty tap name error.
        let network_str = "tap=".to_string();
        assert!(NetConfig::try_from(network_str).is_err());

        // Test case: invalid string.
        let network_str = "blah=blah".to_string();
        assert!(NetConfig::try_from(network_str).is_err());
    }

    #[test]
    fn test_block_config() {
        let block_str = "path=/foo/bar".to_string();
        let block_cfg = BlockConfig::try_from(block_str).unwrap();
        let expected_cfg = BlockConfig {
            path: PathBuf::from("/foo/bar"),
        };
        assert_eq!(block_cfg, expected_cfg);

        // Test case: empty string error.
        assert!(BlockConfig::try_from(String::new()).is_err());

        // Test case: empty tap name error.
        let block_str = "path=".to_string();
        assert!(BlockConfig::try_from(block_str).is_err());

        // Test case: invalid string.
        let block_str = "blah=blah".to_string();
        assert!(BlockConfig::try_from(block_str).is_err());
    }
}
