// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::borrow::{Borrow, BorrowMut};
use std::fs::OpenOptions;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use virtio_blk::stdio_executor::StdIoBackend;
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueT};
use vm_device::bus::MmioAddress;
use vm_device::device_manager::MmioManager;
use vm_device::{DeviceMmio, MutDeviceMmio};
use vm_memory::{GuestAddressSpace, GuestMemoryMmap};

use crate::virtio::block::{BLOCK_DEVICE_ID, VIRTIO_BLK_F_RO};
use crate::virtio::{CommonConfig, Env, SingleFdSignalQueue, QUEUE_MAX_SIZE};

use super::inorder_handler::InOrderQueueHandler;
use super::queue_handler::QueueHandler;
use super::{build_config_space, BlockArgs, Error, Result};

// This Block device can only use the MMIO transport for now, but we plan to reuse large parts of
// the functionality when we implement virtio PCI as well, for example by having a base generic
// type, and then separate concrete instantiations for `MmioConfig` and `PciConfig`.
pub struct Block<M: GuestAddressSpace + Clone + Send + 'static> {
    cfg: CommonConfig<M>,
    file_path: PathBuf,
    read_only: bool,
    // We'll prob need to remember this for state save/restore unless we pass the info from
    // the outside.
    _root_device: bool,
    mem: Arc<GuestMemoryMmap>,
}

impl<M: GuestAddressSpace + Clone + Send + Sync + 'static> Block<M> {
    // Helper method that only creates a `Block` object.
    fn create_block<B>(
        mem: Arc<GuestMemoryMmap>,
        env: &mut Env<M, B>,
        args: &BlockArgs,
    ) -> Result<Self> {
        let device_features = args.device_features();

        // A block device has a single queue.
        let queues = vec![Queue::new(QUEUE_MAX_SIZE).unwrap()];
        let config_space = build_config_space(&args.file_path)?;
        let virtio_cfg = VirtioConfig::new(device_features, queues, config_space);

        let common_cfg = CommonConfig::new(virtio_cfg, env).map_err(Error::Virtio)?;

        Ok(Block {
            mem,
            cfg: common_cfg,
            file_path: args.file_path.clone(),
            read_only: args.read_only,
            _root_device: args.root_device,
        })
    }

    // Create `Block` object, register it on the MMIO bus, and add any extra required info to
    // the kernel cmdline from the environment.
    pub fn new<B>(
        mem: Arc<GuestMemoryMmap>,
        env: &mut Env<M, B>,
        args: &BlockArgs,
    ) -> Result<Arc<Mutex<Self>>>
    where
        // We're using this (more convoluted) bound so we can pass both references and smart
        // pointers such as mutex guards here.
        B: DerefMut,
        B::Target: MmioManager<D = Arc<dyn DeviceMmio + Send + Sync>>,
    {
        let block = Arc::new(Mutex::new(Self::create_block(mem, env, args)?));

        // Register the device on the MMIO bus.
        env.register_mmio_device(block.clone())
            .map_err(Error::Virtio)?;

        env.insert_cmdline_str(args.cmdline_config_substring())
            .map_err(Error::Virtio)?;

        Ok(block)
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> Borrow<VirtioConfig<Queue>> for Block<M> {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        &self.cfg.virtio
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> BorrowMut<VirtioConfig<Queue>> for Block<M> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        &mut self.cfg.virtio
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioDeviceType for Block<M> {
    fn device_type(&self) -> u32 {
        BLOCK_DEVICE_ID
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioDeviceActions for Block<M> {
    type E = Error;

    fn activate(&mut self) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(!self.read_only)
            .open(&self.file_path)
            .map_err(Error::OpenFile)?;

        let mut features = self.cfg.virtio.driver_features;
        if self.read_only {
            // Not sure if the driver is expected to explicitly acknowledge the `RO` feature,
            // so adding it explicitly here when present just in case.
            features |= 1 << VIRTIO_BLK_F_RO;
        }

        // TODO: Create the backend earlier (as part of `Block::new`)?
        let disk = StdIoBackend::new(file, features).map_err(Error::Backend)?;

        let driver_notify = SingleFdSignalQueue {
            irqfd: self.cfg.irqfd.clone(),
            interrupt_status: self.cfg.virtio.interrupt_status.clone(),
        };

        let mut ioevents = self.cfg.prepare_activate().map_err(Error::Virtio)?;

        let inner = InOrderQueueHandler {
            driver_notify,
            queue: self.cfg.virtio.queues.remove(0),
            disk,
        };

        let handler = Arc::new(Mutex::new(QueueHandler {
            mem: self.mem.clone(),
            inner,
            ioeventfd: ioevents.remove(0),
        }));

        self.cfg.finalize_activate(handler).map_err(Error::Virtio)
    }

    fn reset(&mut self) -> Result<()> {
        // Not implemented for now.
        Ok(())
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioMmioDevice for Block<M> {}

impl<M: GuestAddressSpace + Clone + Send + 'static> MutDeviceMmio for Block<M> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use crate::virtio::tests::EnvMock;

    use super::super::VIRTIO_BLK_F_FLUSH;
    use super::*;
    #[test]
    fn test_device() {
        let tmp = TempFile::new().unwrap();

        let mut mock = EnvMock::new();
        let mut env = mock.env();
        let args = BlockArgs {
            file_path: tmp.as_path().to_path_buf(),
            read_only: true,
            root_device: true,
            advertise_flush: true,
        };

        let block_mutex = Block::new(env.mem.clone(), &mut env, &args).unwrap();
        let block = block_mutex.lock().unwrap();

        assert_eq!(block.device_type(), BLOCK_DEVICE_ID);

        assert_eq!(
            mock.kernel_cmdline.as_string().unwrap(),
            format!(
                "virtio_mmio.device=4K@0x{:x}:{} root=/dev/vda ro",
                mock.mmio_cfg.range.base().0,
                mock.mmio_cfg.gsi
            )
        );

        assert_ne!(block.cfg.virtio.device_features & (1 << VIRTIO_BLK_F_RO), 0);
        assert_ne!(
            block.cfg.virtio.device_features & (1 << VIRTIO_BLK_F_FLUSH),
            0
        );
    }
}
