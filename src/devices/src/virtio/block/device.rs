// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};

use virtio_blk::stdio_executor::StdIoBackend;
use virtio_queue::Queue;
use vm_memory::GuestAddressSpace;
use vmm_sys_util::eventfd::EventFd;

use crate::virtio::block::{Error, Result, BLOCK_DEVICE_ID, VIRTIO_BLK_F_RO};
use crate::virtio::{RefVirtioDeviceT, SingleFdSignalQueue, Subscriber};

use super::inorder_handler::InOrderQueueHandler;
use super::queue_handler::QueueHandler;
use super::{build_config_space, BlockArgs};

// This Block device can only use the MMIO transport for now, but we plan to reuse large parts of
// the functionality when we implement virtio PCI as well, for example by having a base generic
// type, and then separate concrete instantiations for `MmioConfig` and `PciConfig`.
pub struct Block {
    args: BlockArgs,
}

impl Block {
    pub fn new(args: BlockArgs) -> Self {
        Block { args }
    }
}

impl RefVirtioDeviceT for Block {
    type E = Error;

    fn device_type(&self) -> u32 {
        BLOCK_DEVICE_ID
    }

    fn cmdline_str(&self) -> Option<String> {
        Some(self.args.cmdline_config_substring())
    }

    fn features(&self) -> u64 {
        self.args.device_features()
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn config_space(&self) -> Result<Vec<u8>> {
        build_config_space(&self.args.file_path)
    }

    fn activate<M: GuestAddressSpace + Send + 'static>(
        &mut self,
        s: SingleFdSignalQueue,
        mut queues: Vec<(Queue<M>, EventFd)>,
        driver_features: u64,
    ) -> Result<Subscriber> {
        let file = OpenOptions::new()
            .read(true)
            .write(!self.args.read_only)
            .open(&self.args.file_path)
            .map_err(Error::OpenFile)?;

        let mut features = driver_features;
        if self.args.read_only {
            // Not sure if the driver is expected to explicitly acknowledge the `RO` feature,
            // so adding it explicitly here when present just in case.
            features |= 1 << VIRTIO_BLK_F_RO;
        }

        // TODO: Create the backend earlier (as part of `Block::new`)?
        let disk = StdIoBackend::new(file, features).map_err(Error::Backend)?;

        let (queue, ioeventfd) = queues.remove(0);

        let inner = InOrderQueueHandler {
            driver_notify: s,
            queue,
            disk,
        };

        let handler = Arc::new(Mutex::new(QueueHandler { inner, ioeventfd }));

        Ok(handler)
    }
}

#[cfg(test)]
mod tests {
    use super::super::VIRTIO_BLK_F_FLUSH;
    use super::*;
    use vmm_sys_util::tempfile::TempFile;

    // Restricting this for now, because registering irqfds does not work on Arm without properly
    // setting up the equivalent of the irqchip first (as part of `EnvMock::new`).
    #[cfg_attr(target_arch = "aarch64", ignore)]
    #[test]
    fn test_device() {
        let tmp = TempFile::new().unwrap();
        let args = BlockArgs {
            file_path: tmp.as_path().to_path_buf(),
            read_only: true,
            root_device: true,
            advertise_flush: true,
        };

        let block = Block::new(args);

        assert_eq!(block.device_type(), BLOCK_DEVICE_ID);
        assert_eq!(block.cmdline_str().unwrap(), "root=/dev/vda ro");

        assert_ne!(block.features() & (1 << VIRTIO_BLK_F_RO), 0);
        assert_ne!(block.features() & (1 << VIRTIO_BLK_F_FLUSH), 0);
    }
}
