// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use crate::virtio::console::CONSOLE_DEVICE_ID;
use crate::virtio::features::{VIRTIO_F_IN_ORDER, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1};

use std::borrow::{Borrow, BorrowMut};
use std::io::stdout;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use virtio_console::console;

use super::inorder_handler::InOrderQueueHandler;
use crate::virtio::console::queue_handler::QueueHandler;
use crate::virtio::{CommonConfig, Env, SingleFdSignalQueue, QUEUE_MAX_SIZE};
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::Queue;
use vm_device::bus::MmioAddress;
use vm_device::device_manager::MmioManager;
use vm_device::{DeviceMmio, MutDeviceMmio};
use vm_memory::GuestAddressSpace;

use super::{Error, Result};

pub struct Console<M: GuestAddressSpace> {
    cfg: CommonConfig<M>,
}

impl<M> Console<M>
where
    M: GuestAddressSpace + Clone + Send + 'static,
{
    pub fn new<B>(env: &mut Env<M, B>) -> Result<Arc<Mutex<Self>>>
    where
        // We're using this (more convoluted) bound so we can pass both references and smart
        // pointers such as mutex guards here.
        B: DerefMut,
        B::Target: MmioManager<D = Arc<dyn DeviceMmio + Send + Sync>>,
    {
        let device_features =
            (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_F_IN_ORDER) | (1 << VIRTIO_F_RING_EVENT_IDX);
        let queues = vec![
            Queue::new(env.mem.clone(), QUEUE_MAX_SIZE),
            Queue::new(env.mem.clone(), QUEUE_MAX_SIZE),
        ];
        // TODO: Add a config space to implement the optional features of the console.
        // For basic operation it can be left empty.
        let config_space = Vec::new();
        let virtio_cfg = VirtioConfig::new(device_features, queues, config_space);
        let common_cfg = CommonConfig::new(virtio_cfg, env).map_err(Error::Virtio)?;
        let console = Arc::new(Mutex::new(Console { cfg: common_cfg }));

        env.register_mmio_device(console.clone())
            .map_err(Error::Virtio)?;

        Ok(console)
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioDeviceType for Console<M> {
    fn device_type(&self) -> u32 {
        CONSOLE_DEVICE_ID
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> Borrow<VirtioConfig<M>> for Console<M> {
    fn borrow(&self) -> &VirtioConfig<M> {
        &self.cfg.virtio
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> BorrowMut<VirtioConfig<M>> for Console<M> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<M> {
        &mut self.cfg.virtio
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioDeviceActions for Console<M> {
    type E = Error;

    fn activate(&mut self) -> Result<()> {
        let driver_notify = SingleFdSignalQueue {
            irqfd: self.cfg.irqfd.clone(),
            interrupt_status: self.cfg.virtio.interrupt_status.clone(),
        };

        let mut ioevents = self.cfg.prepare_activate().map_err(Error::Virtio)?;

        let inner = InOrderQueueHandler {
            driver_notify,
            receiveq: self.cfg.virtio.queues.remove(0),
            transmitq: self.cfg.virtio.queues.remove(0),
            console: console::Console::new_with_capacity(console::DEFAULT_CAPACITY, stdout())
                .map_err(Error::Console)?,
        };

        let handler = Arc::new(Mutex::new(QueueHandler {
            inner,
            receiveqfd: ioevents.remove(0),
            transmitqfd: ioevents.remove(0),
        }));

        self.cfg.finalize_activate(handler).map_err(Error::Virtio)
    }

    fn reset(&mut self) -> Result<()> {
        // Not implemented for now.
        Ok(())
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> VirtioMmioDevice<M> for Console<M> {}

impl<M: GuestAddressSpace + Clone + Send + 'static> MutDeviceMmio for Console<M> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}
