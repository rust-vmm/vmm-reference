// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::sync::Arc;

use event_manager::{MutEventSubscriber, RemoteEndpoint, Result as EvmgrResult, SubscriberId};
use kvm_ioctls::{IoEventAddress, VmFd};
use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vm_memory::GuestAddressSpace;
use vm_virtio::devices::{VirtioConfig, VirtioMmioDevice, WithDeviceOps, WithVirtioConfig};
use vm_virtio::Queue;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::virtio::block::request::DiskProperties;
use crate::virtio::block::BLOCK_DEVICE_ID;
use crate::virtio::features::{VIRTIO_F_IN_ORDER, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1};
use crate::virtio::{
    MmioConfig, SingleFdSignalQueue, QUEUE_MAX_SIZE, VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET,
};

use super::handler::QueueHandler;
use super::simple_handler::SimpleHandler;
use super::{build_config_space, BlockArgs, Error, Result, VIRTIO_BLK_F_FLUSH};

// This Block device can only use the MMIO transport for now, but we plan to reuse large parts of
// the functionality when we implement virtio PCI as well, for example by having a base generic
// type, and then separate concrete instantiations for `MmioConfig` and `PciConfig`.
pub struct Block<M: GuestAddressSpace> {
    virtio_cfg: VirtioConfig<M>,
    mmio_cfg: MmioConfig,
    endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
    vm_fd: Arc<VmFd>,
    irqfd: Arc<EventFd>,
    file_path: String,
}

impl<M: GuestAddressSpace + Clone> Block<M> {
    pub fn new(args: BlockArgs<M>) -> Result<Self> {
        // The queue handling logic for this device uses the buffers in order, so we enable the
        // corresponding feature as well.
        let device_features =
            VIRTIO_F_VERSION_1 | VIRTIO_F_IN_ORDER | VIRTIO_F_RING_EVENT_IDX | VIRTIO_BLK_F_FLUSH;

        // A block device has a single queue.
        let queues = vec![Queue::new(args.mem, QUEUE_MAX_SIZE)];
        let config_space = build_config_space(&args.file_path)?;
        let virtio_cfg = VirtioConfig::new(device_features, queues, config_space);

        let irqfd = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        args.vm_fd
            .register_irqfd(&irqfd, args.mmio_cfg.gsi)
            .map_err(Error::RegisterIrqfd)?;

        Ok(Block {
            virtio_cfg,
            mmio_cfg: args.mmio_cfg,
            endpoint: args.endpoint,
            vm_fd: args.vm_fd,
            irqfd: Arc::new(irqfd),
            file_path: args.file_path,
        })
    }
}

// We now implement `WithVirtioConfig` and `WithDeviceOps` to get the automatic implementation
// for `VirtioDevice`.
impl<M: GuestAddressSpace + Clone + Send + 'static> WithVirtioConfig<M> for Block<M> {
    fn device_type(&self) -> u32 {
        BLOCK_DEVICE_ID
    }

    fn virtio_config(&self) -> &VirtioConfig<M> {
        &self.virtio_cfg
    }

    fn virtio_config_mut(&mut self) -> &mut VirtioConfig<M> {
        &mut self.virtio_cfg
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> WithDeviceOps for Block<M> {
    type E = Error;

    fn activate(&mut self) -> Result<()> {
        if self.virtio_cfg.device_activated {
            return Err(Error::AlreadyActivated);
        }

        if !self.queues_valid() {
            return Err(Error::QueuesNotValid);
        }

        // We do not support legacy drivers.
        if self.virtio_cfg.driver_features & VIRTIO_F_VERSION_1 == 0 {
            return Err(Error::BadFeatures(self.virtio_cfg.driver_features));
        }

        // Set the appropriate queue configuration flag if the `EVENT_IDX` features has been
        // negotiated.
        if self.virtio_cfg.driver_features & VIRTIO_F_RING_EVENT_IDX != 0 {
            self.virtio_cfg.queues[0].set_event_idx(true);
        }

        let ioeventfd = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;

        // Register the queue event fd.
        self.vm_fd
            .register_ioevent(
                &ioeventfd,
                &IoEventAddress::Mmio(
                    self.mmio_cfg.range.base().0 + VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET,
                ),
                0u32,
            )
            .map_err(Error::RegisterIoevent)?;

        let disk = DiskProperties::new(self.file_path.clone(), false).map_err(Error::Backend)?;

        let driver_notify = SingleFdSignalQueue {
            irqfd: self.irqfd.clone(),
            interrupt_status: self.virtio_cfg.interrupt_status.clone(),
        };

        let inner = SimpleHandler {
            driver_notify,
            queue: self.virtio_cfg.queues[0].clone(),
            disk,
        };

        let handler = QueueHandler { inner, ioeventfd };

        // We use the model where the queue handler we've instantiated is passed into the
        // ownership of the event manager below. We can also experiment to see if there's any
        // noticeable difference between this approach and the one with an `Arc<Mutex<dyn ...>`
        // wrapper, and then pick the more convenient one.

        // We could record the `sub_id` for further interaction (i.e. to retrieve state at a
        // later time).
        let _sub_id = self
            .endpoint
            .call_blocking(move |mgr| -> EvmgrResult<SubscriberId> {
                Ok(mgr.add_subscriber(Box::new(handler)))
            })
            .map_err(Error::Endpoint)?;

        self.virtio_cfg.device_activated = true;

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        // Not implemented for now.
        Ok(())
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioMmioDevice<M> for Block<M> {}

impl<M: GuestAddressSpace + Clone + Send + 'static> MutDeviceMmio for Block<M> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}
