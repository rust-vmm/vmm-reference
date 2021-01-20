// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Config builder
use std::convert::TryFrom;

use super::{
    BlockConfig, ConversionError, KernelConfig, MemoryConfig, NetConfig, VMMConfig, VcpuConfig,
};

/// Builder structure for VMMConfig
#[derive(Debug)]
pub struct Builder {
    inner: Result<VMMConfig, ConversionError>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            inner: Ok(VMMConfig::default()),
        }
    }

    pub fn build(&self) -> Result<VMMConfig, ConversionError> {
        // Check if there are any errors
        match &self.inner {
            Ok(vc) => {
                // Empty kernel image path.
                if vc.kernel_config.path.to_str().unwrap().is_empty() {
                    return Err(ConversionError::ParseKernel(
                        "Kernel Image Path is Empty.".to_string(),
                    ));
                }
            }
            Err(_) => {}
        }

        self.inner.clone()
    }

    pub fn memory_config<T>(self, memory: Option<T>) -> Self
    where
        MemoryConfig: TryFrom<T>,
        <MemoryConfig as TryFrom<T>>::Error: Into<ConversionError>,
    {
        match memory {
            Some(m) => self.and_then(|mut config| {
                config.memory_config = TryFrom::try_from(m).map_err(Into::into)?;
                Ok(config)
            }),
            None => self,
        }
    }

    pub fn vcpu_config<T>(self, vcpu: Option<T>) -> Self
    where
        VcpuConfig: TryFrom<T>,
        <VcpuConfig as TryFrom<T>>::Error: Into<ConversionError>,
    {
        match vcpu {
            Some(v) => self.and_then(|mut config| {
                config.vcpu_config = TryFrom::try_from(v).map_err(Into::into)?;
                Ok(config)
            }),
            None => self,
        }
    }

    pub fn kernel_config<T>(self, kernel: Option<T>) -> Self
    where
        KernelConfig: TryFrom<T>,
        <KernelConfig as TryFrom<T>>::Error: Into<ConversionError>,
    {
        match kernel {
            Some(k) => self.and_then(|mut config| {
                config.kernel_config = TryFrom::try_from(k).map_err(Into::into)?;
                Ok(config)
            }),
            None => self,
        }
    }

    pub fn network_config<T>(self, network: Option<T>) -> Self
    where
        NetConfig: TryFrom<T>,
        <NetConfig as TryFrom<T>>::Error: Into<ConversionError>,
    {
        match network {
            Some(n) => self.and_then(|mut config| {
                config.network_config = Some(TryFrom::try_from(n).map_err(Into::into)?);
                Ok(config)
            }),
            None => self,
        }
    }

    pub fn block_config<T>(self, block: Option<T>) -> Self
    where
        BlockConfig: TryFrom<T>,
        <BlockConfig as TryFrom<T>>::Error: Into<ConversionError>,
    {
        match block {
            Some(b) => self.and_then(|mut config| {
                config.block_config = Some(TryFrom::try_from(b).map_err(Into::into)?);
                Ok(config)
            }),
            None => self,
        }
    }

    fn and_then<F>(self, func: F) -> Self
    where
        F: FnOnce(VMMConfig) -> Result<VMMConfig, ConversionError>,
    {
        Builder {
            inner: self.inner.and_then(func),
        }
    }
}
