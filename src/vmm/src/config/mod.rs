// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::convert::TryFrom;
use std::fmt;
use std::num;
use std::path::PathBuf;
use std::result;

use arg_parser::CfgArgParser;

use super::{DEFAULT_HIGH_RAM_START, DEFAULT_KERNEL_CMDLINE};

mod arg_parser;

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
}

impl ConversionError {
    fn new_kernel<T: fmt::Display>(err: T) -> Self {
        Self::ParseKernel(err.to_string())
    }
    fn new_memory<T: fmt::Display>(err: T) -> Self {
        Self::ParseMemory(err.to_string())
    }
    fn new_vcpus<T: fmt::Display>(err: T) -> Self {
        Self::ParseVcpus(err.to_string())
    }
    fn new_block<T: fmt::Display>(err: T) -> Self {
        Self::ParseBlock(err.to_string())
    }
    fn new_network<T: fmt::Display>(err: T) -> Self {
        Self::ParseNetwork(err.to_string())
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConversionError::*;
        match self {
            ParseKernel(ref s) => write!(f, "Invalid input for kernel: {}", s),
            ParseMemory(ref s) => write!(f, "Invalid input for memory: {}", s),
            ParseVcpus(ref s) => write!(f, "Invalid input for vCPUs: {}", s),
            ParseNetwork(ref s) => write!(f, "Invalid input for network: {}", s),
            ParseBlock(ref s) => write!(f, "Invalid input for network: {}", s),
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
        let mut arg_parser = CfgArgParser::new(mem_cfg_str);

        let size_mib = arg_parser
            .value_of("size_mib")
            .map_err(ConversionError::new_memory)?
            .unwrap_or(256);
        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_memory)?;
        Ok(MemoryConfig { size_mib })
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
        // Supported options: `num=<u8>`
        let mut arg_parser = CfgArgParser::new(vcpu_cfg_str);
        let num = arg_parser
            .value_of("num")
            .map_err(ConversionError::new_vcpus)?
            .unwrap_or_else(|| num::NonZeroU8::new(1).unwrap());
        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_vcpus)?;
        Ok(VcpuConfig { num: num.into() })
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
        let mut arg_parser = CfgArgParser::new(kernel_cfg_str);
        let cmdline = arg_parser
            .value_of("cmdline")
            .map_err(ConversionError::new_kernel)?
            .unwrap_or_else(|| DEFAULT_KERNEL_CMDLINE.to_string());

        let path = arg_parser
            .value_of("path")
            .map_err(ConversionError::new_kernel)?
            .ok_or_else(|| ConversionError::new_kernel("Missing required argument: path"))?;

        let himem_start = arg_parser
            .value_of("himem_start")
            .map_err(ConversionError::new_kernel)?
            .unwrap_or(DEFAULT_HIGH_RAM_START);

        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_kernel)?;
        Ok(KernelConfig {
            cmdline,
            path,
            himem_start,
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
        let mut arg_parser = CfgArgParser::new(net_config_str);

        let tap_name = arg_parser
            .value_of("tap")
            .map_err(ConversionError::new_network)?
            .ok_or_else(|| ConversionError::new_network("Missing required argument: tap"))?;

        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_network)?;
        Ok(NetConfig { tap_name })
    }
}

/// Block device configuration
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BlockConfig {
    /// Path to the block device backend.
    pub path: PathBuf,
}

impl TryFrom<String> for BlockConfig {
    type Error = ConversionError;

    fn try_from(block_cfg_str: String) -> Result<Self, Self::Error> {
        // Supported options: `path=PathBuf`
        let mut arg_parser = CfgArgParser::new(block_cfg_str);

        let path = arg_parser
            .value_of("path")
            .map_err(ConversionError::new_block)?
            .ok_or_else(|| ConversionError::new_block("Missing required argument: path"))?;

        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_block)?;
        Ok(BlockConfig { path })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_config() {
        // Check that additional commas in the kernel string do not cause a panic.
        let kernel_str = r#"path=/foo/bar,cmdline="foo=bar",himem_start=42,"#;
        let expected_kernel_config = KernelConfig {
            cmdline: r#""foo=bar""#.to_string(),
            himem_start: 42,
            path: PathBuf::from("/foo/bar"),
        };
        assert_eq!(
            KernelConfig::try_from(kernel_str.to_string()).unwrap(),
            expected_kernel_config
        );

        // Check that an empty path returns a conversion error.
        let kernel_str = r#"path=,cmdline="foo=bar",himem_start=42,"#;
        assert_eq!(
            KernelConfig::try_from(kernel_str.to_string()).unwrap_err(),
            ConversionError::ParseKernel("Missing required argument: path".to_string())
        );
        assert!(KernelConfig::try_from("path=/something,not=valid".to_string()).is_err());
        assert!(KernelConfig::try_from("path=/something,himem_start=invalid".to_string()).is_err());
    }

    #[test]
    fn test_vcpu_config() {
        // Invalid vCPU numbers: 0, 256 (exceeds the u8 limit).
        let vcpu_str = "num=0";
        assert_eq!(
            VcpuConfig::try_from(vcpu_str.to_string()).unwrap_err(),
            ConversionError::ParseVcpus(
                "Param \'num\', parsing failed: number would be zero for non-zero type".to_string()
            )
        );

        let vcpu_str = "num=256";
        assert_eq!(
            VcpuConfig::try_from(vcpu_str.to_string()).unwrap_err(),
            ConversionError::ParseVcpus(
                "Param 'num', parsing failed: number too large to fit in target type".to_string()
            )
        );

        // Missing vCPU number in config string, use default
        let vcpu_str = "num=";
        assert!(VcpuConfig::try_from(vcpu_str.to_string()).is_ok());

        // vCPU number parsing error
        let vcpu_str = "num=abc";
        assert!(VcpuConfig::try_from(vcpu_str.to_string()).is_err());

        // Extra argument
        let vcpu_str = "num=1,foo=bar";
        assert!(VcpuConfig::try_from(vcpu_str.to_string()).is_err());
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

        // Test case: unused parameters
        let network_str = "tap=something,blah=blah".to_string();
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

        // Test case: empty path error.
        let block_str = "path=".to_string();
        assert!(BlockConfig::try_from(block_str).is_err());

        // Test case: invalid string.
        let block_str = "blah=blah".to_string();
        assert!(BlockConfig::try_from(block_str).is_err());

        // Test case: unused parameters
        let block_str = "path=/foo/bar,blah=blah".to_string();
        assert!(BlockConfig::try_from(block_str).is_err());
    }

    #[test]
    fn test_memory_config() {
        let default = MemoryConfig { size_mib: 256 };
        let size_str = "size_mib=42".to_string();
        let memory_cfg = MemoryConfig::try_from(size_str).unwrap();
        let expected_cfg = MemoryConfig { size_mib: 42 };
        assert_eq!(memory_cfg, expected_cfg);

        // Test case: empty string should use default
        assert_eq!(MemoryConfig::try_from(String::new()).unwrap(), default);

        // Test case: empty size_mib, use default
        let memory_str = "size_mib=".to_string();
        assert!(MemoryConfig::try_from(memory_str).is_ok());

        // Test case: size_mib invalid input
        let memory_str = "size_mib=ciao".to_string();
        assert!(MemoryConfig::try_from(memory_str).is_err());

        // Test case: invalid string.
        let memory_str = "blah=blah".to_string();
        assert_eq!(
            MemoryConfig::try_from(memory_str).unwrap_err(),
            ConversionError::ParseMemory("Unknown arguments found: \'blah\'".to_string())
        );

        // Test case: unused parameters
        let memory_str = "size_mib=12,blah=blah".to_string();
        assert!(MemoryConfig::try_from(memory_str).is_err());
    }
}
