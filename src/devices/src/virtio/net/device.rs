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

use crate::virtio::features::{VIRTIO_F_IN_ORDER, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1};
use crate::virtio::net::{Error, NetArgs, Result, NET_DEVICE_ID};
use crate::virtio::{
    MmioConfig, SingleFdSignalQueue, QUEUE_MAX_SIZE, VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET,
};

use super::bindings;
use super::features::*;
use super::handler::QueueHandler;
use super::simple_handler::SimpleHandler;
use super::tap::Tap;

pub struct Net<M: GuestAddressSpace> {
    virtio_cfg: VirtioConfig<M>,
    mmio_cfg: MmioConfig,
    endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
    vm_fd: Arc<VmFd>,
    irqfd: Arc<EventFd>,
    tap_name: String,
}

impl<M: GuestAddressSpace + Clone + Send + 'static> Net<M> {
    pub fn new(args: NetArgs<M>) -> Result<Self> {
        let device_features = VIRTIO_F_VERSION_1
            | VIRTIO_F_RING_EVENT_IDX
            | VIRTIO_F_IN_ORDER
            | VIRTIO_NET_F_CSUM
            | VIRTIO_NET_F_GUEST_CSUM
            | VIRTIO_NET_F_GUEST_TSO4
            | VIRTIO_NET_F_GUEST_UFO
            | VIRTIO_NET_F_HOST_TSO4
            | VIRTIO_NET_F_HOST_UFO;

        let queues = vec![Queue::new(args.mem.clone(), QUEUE_MAX_SIZE); 2];
        // TODO: We'll need a minimal config space to support setting an explicit MAC addr
        // on the guest interface at least. We use an empty one for now.
        let config_space = Vec::new();
        let virtio_cfg = VirtioConfig::new(device_features, queues, config_space);

        let irqfd = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        args.vm_fd
            .register_irqfd(&irqfd, args.mmio_cfg.gsi)
            .map_err(Error::RegisterIrqfd)?;

        Ok(Net {
            virtio_cfg,
            mmio_cfg: args.mmio_cfg,
            endpoint: args.endpoint,
            vm_fd: args.vm_fd,
            irqfd: Arc::new(irqfd),
            tap_name: args.tap_name,
        })
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> WithVirtioConfig<M> for Net<M> {
    fn device_type(&self) -> u32 {
        NET_DEVICE_ID
    }

    fn virtio_config(&self) -> &VirtioConfig<M> {
        &self.virtio_cfg
    }

    fn virtio_config_mut(&mut self) -> &mut VirtioConfig<M> {
        &mut self.virtio_cfg
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> WithDeviceOps for Net<M> {
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
            for queue in self.virtio_cfg.queues.iter_mut() {
                queue.set_event_idx(true);
            }
        }

        let rx_ioevent = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        let tx_ioevent = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;

        self.vm_fd
            .register_ioevent(
                &rx_ioevent,
                // super super hard-coded
                &IoEventAddress::Mmio(
                    self.mmio_cfg.range.base().0 + VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET,
                ),
                0u32,
            )
            .map_err(Error::RegisterIoevent)?;

        self.vm_fd
            .register_ioevent(
                &tx_ioevent,
                // super super hard-coded
                &IoEventAddress::Mmio(
                    self.mmio_cfg.range.base().0 + VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET,
                ),
                1u32,
            )
            .map_err(Error::RegisterIoevent)?;

        let rxq = self.virtio_cfg.queues[0].clone();
        let txq = self.virtio_cfg.queues[1].clone();

        // Hardcoded for now.
        let tap = Tap::open_named(self.tap_name.as_str()).map_err(Error::Tap)?;

        // Set offload flags to match the relevant virtio features of the device (for now,
        // statically set in the constructor.
        tap.set_offload(
            bindings::TUN_F_CSUM
                | bindings::TUN_F_UFO
                | bindings::TUN_F_TSO4
                | bindings::TUN_F_TSO6,
        )
        .map_err(Error::Tap)?;

        // The layout of the header is specified in the standard and is 12 bytes in size. We
        // should define this somewhere.
        tap.set_vnet_hdr_size(12).map_err(Error::Tap)?;

        let driver_notify = SingleFdSignalQueue {
            irqfd: self.irqfd.clone(),
            interrupt_status: self.virtio_cfg.interrupt_status.clone(),
        };
        let inner = SimpleHandler::new(driver_notify, rxq, txq, tap);

        let handler = QueueHandler {
            inner,
            rx_ioevent,
            tx_ioevent,
        };

        let _sub_id = self
            .endpoint
            .call_blocking(move |mgr| -> EvmgrResult<SubscriberId> {
                Ok(mgr.add_subscriber(Box::new(handler)))
            })
            .map_err(Error::Endpoint)?;

        self.virtio_cfg.device_activated = true;

        Ok(())
    }

    fn reset(&mut self) -> std::result::Result<(), Error> {
        // Not implemented for now.
        Ok(())
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioMmioDevice<M> for Net<M> {}

impl<M: GuestAddressSpace + Clone + Send + 'static> MutDeviceMmio for Net<M> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}
