// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::convert::TryFrom;
use std::fmt;
use std::num;
use std::path::PathBuf;
use std::result;

use linux_loader::cmdline::Cmdline;

use arg_parser::CfgArgParser;
use builder::Builder;

use super::{DEFAULT_KERNEL_CMDLINE, DEFAULT_KERNEL_LOAD_ADDR};

mod arg_parser;
mod builder;

const KERNEL_CMDLINE_CAPACITY: usize = 4096;

/// Errors encountered converting the `*Config` objects.
#[derive(Clone, Debug, PartialEq)]
pub enum ConversionError {
    /// Failed to parse the string representation for the kernel.
    ParseKernel(String),
    /// Failed to parse the string representation for guest memory.
    ParseMemory(String),
    /// Failed to parse the string representation for the vCPUs.
    ParseVcpus(String),
    /// Failed to parse the string representation for the network.
    ParseNet(String),
    /// Failed to parse the string representation for the block.
    ParseBlock(String),
    /// Failed to parse the string representation for the serial config.
    ParseSerial(String),
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
    fn new_net<T: fmt::Display>(err: T) -> Self {
        Self::ParseNet(err.to_string())
    }
    fn new_serial<T: fmt::Display>(err: T) -> Self {
        Self::ParseSerial(err.to_string())
    }
}

impl VMMConfig {
    /// Builds a builder
    pub fn builder() -> Builder {
        Builder::new()
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConversionError::*;
        match self {
            ParseKernel(ref s) => write!(f, "Invalid input for kernel: {}", s),
            ParseMemory(ref s) => write!(f, "Invalid input for memory: {}", s),
            ParseVcpus(ref s) => write!(f, "Invalid input for vCPUs: {}", s),
            ParseNet(ref s) => write!(f, "Invalid input for network: {}", s),
            ParseBlock(ref s) => write!(f, "Invalid input for block: {}", s),
            ParseSerial(ref s) => write!(f, "Invalid input for serial: {}", s),
        }
    }
}

/// Guest memory configurations.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryConfig {
    /// Guest memory size in MiB.
    pub size_mib: u32,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig { size_mib: 256u32 }
    }
}

impl TryFrom<&str> for MemoryConfig {
    type Error = ConversionError;

    fn try_from(mem_cfg_str: &str) -> result::Result<Self, Self::Error> {
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
#[derive(Clone, Debug, PartialEq)]
pub struct VcpuConfig {
    /// Number of vCPUs.
    pub num: u8,
}

impl Default for VcpuConfig {
    fn default() -> Self {
        VcpuConfig { num: 1u8 }
    }
}

impl TryFrom<&str> for VcpuConfig {
    type Error = ConversionError;

    fn try_from(vcpu_cfg_str: &str) -> result::Result<Self, Self::Error> {
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
#[derive(Clone, Debug, PartialEq)]
pub struct KernelConfig {
    /// Kernel command line.
    pub cmdline: Cmdline,
    /// Path to the kernel image.
    pub path: PathBuf,
    /// Address where the kernel is loaded.
    pub load_addr: u64,
}

impl KernelConfig {
    /// Return the default kernel command line used by the Vmm.
    pub fn default_cmdline() -> Cmdline {
        let mut cmdline = Cmdline::new(KERNEL_CMDLINE_CAPACITY);

        // It's ok to use `unwrap` because the initial capacity of `cmdline` should be
        // sufficient to accommodate the default kernel cmdline.
        cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();

        cmdline
    }
}

impl Default for KernelConfig {
    fn default() -> Self {
        KernelConfig {
            cmdline: KernelConfig::default_cmdline(),
            path: PathBuf::from(""), // FIXME: make it a const.
            load_addr: DEFAULT_KERNEL_LOAD_ADDR,
        }
    }
}

impl TryFrom<&str> for KernelConfig {
    type Error = ConversionError;

    fn try_from(kernel_cfg_str: &str) -> result::Result<Self, Self::Error> {
        // Supported options:
        // `cmdline=<"string">,path=/path/to/kernel,kernel_load_addr=<u64>`
        // Required: path
        let mut arg_parser = CfgArgParser::new(kernel_cfg_str);

        let cmdline_str = arg_parser
            .value_of("cmdline")
            .map_err(ConversionError::new_kernel)?
            .unwrap_or_else(|| DEFAULT_KERNEL_CMDLINE.to_string());

        let mut cmdline = Cmdline::new(KERNEL_CMDLINE_CAPACITY);
        cmdline
            .insert_str(cmdline_str)
            .map_err(|_| ConversionError::new_kernel("Kernel cmdline capacity error"))?;

        let path = arg_parser
            .value_of("path")
            .map_err(ConversionError::new_kernel)?
            .ok_or_else(|| ConversionError::new_kernel("Missing required argument: path"))?;

        let load_addr = arg_parser
            .value_of("kernel_load_addr")
            .map_err(ConversionError::new_kernel)?
            .unwrap_or(DEFAULT_KERNEL_LOAD_ADDR);

        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_kernel)?;
        Ok(KernelConfig {
            cmdline,
            path,
            load_addr,
        })
    }
}
/// Network device configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct NetConfig {
    /// Name of tap device.
    pub tap_name: String,
}

impl TryFrom<&str> for NetConfig {
    type Error = ConversionError;

    fn try_from(net_config_str: &str) -> Result<Self, Self::Error> {
        // Supported options: `tap=String`
        let mut arg_parser = CfgArgParser::new(net_config_str);

        let tap_name = arg_parser
            .value_of("tap")
            .map_err(ConversionError::new_net)?
            .ok_or_else(|| ConversionError::new_net("Missing required argument: tap"))?;

        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_net)?;
        Ok(NetConfig { tap_name })
    }
}

/// Serial communication configuration
#[derive(Clone, Debug, PartialEq)]
pub struct SerialConfig {
    /// Optional path to pipe the input of the guest OS.
    pub serial_input: Option<PathBuf>,
    /// Optional path to pipe the output of the guest OS.
    pub serial_output: Option<PathBuf>,
}

impl Default for SerialConfig {
    fn default() -> Self {
        SerialConfig {
            serial_input: None,
            serial_output: None,
        }
    }
}

impl TryFrom<&str> for SerialConfig {
    type Error = ConversionError;

    fn try_from(serial_console_str: &str) -> Result<Self, Self::Error> {
        let mut arg_parser = CfgArgParser::new(serial_console_str);

        let serial_input = arg_parser
            .value_of::<String>("serial_input")
            .map_err(ConversionError::new_serial)?
            .map(PathBuf::from);

        let serial_output = arg_parser
            .value_of::<String>("serial_output")
            .map_err(ConversionError::new_serial)?
            .map(PathBuf::from);

        arg_parser
            .all_consumed()
            .map_err(ConversionError::new_serial)?;
        Ok(SerialConfig {
            serial_input,
            serial_output,
        })
    }
}

/// Block device configuration
#[derive(Clone, Debug, PartialEq)]
pub struct BlockConfig {
    /// Path to the block device backend.
    pub path: PathBuf,
}

impl TryFrom<&str> for BlockConfig {
    type Error = ConversionError;

    fn try_from(block_cfg_str: &str) -> Result<Self, Self::Error> {
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
    pub net_config: Option<NetConfig>,
    /// Block device configuration.
    pub block_config: Option<BlockConfig>,
    /// Serial communication configuration.
    pub serial_config: SerialConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_config() {
        // Check that additional commas in the kernel string do not cause a panic.
        let kernel_str = r#"path=/foo/bar,cmdline="foo=bar",kernel_load_addr=42,"#;

        let mut foo_cmdline = Cmdline::new(128);
        foo_cmdline.insert_str("\"foo=bar\"").unwrap();

        let expected_kernel_config = KernelConfig {
            cmdline: foo_cmdline,
            load_addr: 42,
            path: PathBuf::from("/foo/bar"),
        };
        assert_eq!(
            KernelConfig::try_from(kernel_str).unwrap(),
            expected_kernel_config
        );

        // Check that an empty path returns a conversion error.
        let kernel_str = r#"path=,cmdline="foo=bar",kernel_load_addr=42,"#;
        assert_eq!(
            KernelConfig::try_from(kernel_str).unwrap_err(),
            ConversionError::ParseKernel("Missing required argument: path".to_string())
        );
        assert!(KernelConfig::try_from("path=/something,not=valid").is_err());
        assert!(KernelConfig::try_from("path=/something,kernel_load_addr=invalid").is_err());
    }

    #[test]
    fn test_vcpu_config() {
        // Invalid vCPU numbers: 0, 256 (exceeds the u8 limit).
        let vcpu_str = "num=0";
        assert_eq!(
            VcpuConfig::try_from(vcpu_str).unwrap_err(),
            ConversionError::ParseVcpus(
                "Param \'num\', parsing failed: number would be zero for non-zero type".to_string()
            )
        );

        let vcpu_str = "num=256";
        assert_eq!(
            VcpuConfig::try_from(vcpu_str).unwrap_err(),
            ConversionError::ParseVcpus(
                "Param 'num', parsing failed: number too large to fit in target type".to_string()
            )
        );

        // Missing vCPU number in config string, use default
        let vcpu_str = "num=";
        assert!(VcpuConfig::try_from(vcpu_str).is_ok());

        // vCPU number parsing error
        let vcpu_str = "num=abc";
        assert!(VcpuConfig::try_from(vcpu_str).is_err());

        // Extra argument
        let vcpu_str = "num=1,foo=bar";
        assert!(VcpuConfig::try_from(vcpu_str).is_err());
    }

    #[test]
    fn test_net_config() {
        let net_str = "tap=vmtap";
        let net_cfg = NetConfig::try_from(net_str).unwrap();
        let expected_cfg = NetConfig {
            tap_name: "vmtap".to_string(),
        };
        assert_eq!(net_cfg, expected_cfg);

        // Test case: empty string error.
        assert!(NetConfig::try_from("").is_err());

        // Test case: empty tap name error.
        let net_str = "tap=";
        assert!(NetConfig::try_from(net_str).is_err());

        // Test case: invalid string.
        let net_str = "blah=blah";
        assert!(NetConfig::try_from(net_str).is_err());

        // Test case: unused parameters
        let net_str = "tap=something,blah=blah";
        assert!(NetConfig::try_from(net_str).is_err());
    }

    #[test]
    fn test_block_config() {
        let block_str = "path=/foo/bar";
        let block_cfg = BlockConfig::try_from(block_str).unwrap();
        let expected_cfg = BlockConfig {
            path: PathBuf::from("/foo/bar"),
        };
        assert_eq!(block_cfg, expected_cfg);

        // Test case: empty string error.
        assert!(BlockConfig::try_from("").is_err());

        // Test case: empty tap name error.
        let block_str = "path=";
        assert!(BlockConfig::try_from(block_str).is_err());

        // Test case: invalid string.
        let block_str = "blah=blah";
        assert!(BlockConfig::try_from(block_str).is_err());

        // Test case: unused parameters
        let block_str = "path=/foo/bar,blah=blah";
        assert!(BlockConfig::try_from(block_str).is_err());
    }

    #[test]
    fn test_serial_config() {
        // Testing the positive case with both input and output
        let serial_str = r#"serial_input=/foo/bar/in,serial_output=/foo/bar/out"#;
        let serial_cfg = SerialConfig::try_from(serial_str).unwrap();
        let expected_cfg = SerialConfig {
            serial_input: Some(PathBuf::from(String::from("/foo/bar/in"))),
            serial_output: Some(PathBuf::from(String::from("/foo/bar/out"))),
        };
        assert_eq!(serial_cfg, expected_cfg);

        // Testing that the config is succesfully created with empty str for input
        let serial_str_empty_in = r#"serial_input=,serial_output=/foo/bar/out"#;
        let serial_cfg_empty_in = SerialConfig::try_from(serial_str_empty_in).unwrap();
        let expected_cfg_empty_in = SerialConfig {
            serial_input: None,
            serial_output: Some(PathBuf::from(String::from("/foo/bar/out"))),
        };
        assert_eq!(serial_cfg_empty_in, expected_cfg_empty_in);

        // Testing that the config is succesfully created with empty str for output
        let serial_str_empty_out = r#"serial_input=/foo/bar/in,serial_output="#;
        let serial_cfg_empty_out = SerialConfig::try_from(serial_str_empty_out).unwrap();
        let expected_cfg_empty_out = SerialConfig {
            serial_input: Some(PathBuf::from(String::from("/foo/bar/in"))),
            serial_output: None,
        };
        assert_eq!(serial_cfg_empty_out, expected_cfg_empty_out);

        // Testing that the config is succesfully created without input
        let serial_str_no_in = r#"serial_output=/foo/bar/out"#;
        let serial_cfg_no_in = SerialConfig::try_from(serial_str_no_in).unwrap();
        let expected_cfg_no_in = SerialConfig {
            serial_input: None,
            serial_output: Some(PathBuf::from(String::from("/foo/bar/out"))),
        };
        assert_eq!(serial_cfg_no_in, expected_cfg_no_in);

        // Testing that the config is succesfully created without output
        let serial_str_no_out = r#"serial_input=/foo/bar/in"#;
        let serial_cfg_no_out = SerialConfig::try_from(serial_str_no_out).unwrap();
        let expected_cfg_no_out = SerialConfig {
            serial_input: Some(PathBuf::from(String::from("/foo/bar/in"))),
            serial_output: None,
        };
        assert_eq!(serial_cfg_no_out, expected_cfg_no_out);

        // Testing that the config is succesfully created for an empty string
        let serial_str_empty = r#""#;
        let serial_cfg_empty = SerialConfig::try_from(serial_str_empty).unwrap();
        let expected_cfg_empty = SerialConfig {
            serial_input: None,
            serial_output: None,
        };
        assert_eq!(serial_cfg_empty, expected_cfg_empty);

        // Testing that the invalid string raises an error
        let serial_str_invalid = r#"invalid"#;
        assert!(SerialConfig::try_from(serial_str_invalid).is_err());
    }

    #[test]
    fn test_memory_config() {
        let default = MemoryConfig { size_mib: 256 };
        let size_str = "size_mib=42";
        let memory_cfg = MemoryConfig::try_from(size_str).unwrap();
        let expected_cfg = MemoryConfig { size_mib: 42 };
        assert_eq!(memory_cfg, expected_cfg);

        // Test case: empty string should use default
        assert_eq!(MemoryConfig::try_from("").unwrap(), default);

        // Test case: empty size_mib, use default
        let memory_str = "size_mib=";
        assert!(MemoryConfig::try_from(memory_str).is_ok());

        // Test case: size_mib invalid input
        let memory_str = "size_mib=ciao";
        assert!(MemoryConfig::try_from(memory_str).is_err());

        // Test case: invalid string.
        let memory_str = "blah=blah";
        assert_eq!(
            MemoryConfig::try_from(memory_str).unwrap_err(),
            ConversionError::ParseMemory("Unknown arguments found: \'blah\'".to_string())
        );

        // Test case: unused parameters
        let memory_str = "size_mib=12,blah=blah";
        assert!(MemoryConfig::try_from(memory_str).is_err());
    }
}
