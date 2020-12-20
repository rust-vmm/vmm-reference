use std::borrow::{Borrow, BorrowMut};
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use vm_device::bus::MmioAddress;
use vm_device::device_manager::MmioManager;
use vm_device::{DeviceMmio, MutDeviceMmio};
use vm_memory::GuestAddressSpace;
use vm_virtio::device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use vm_virtio::Queue;

use crate::virtio::features::{VIRTIO_F_IN_ORDER, VIRTIO_F_VERSION_1};
use crate::virtio::{CommonConfig, Env, Error as VirtioError, SingleFdSignalQueue, QUEUE_MAX_SIZE};

use super::inorder_handler::InOrderHandler;
use super::queue_handler::QueueHandler;
use super::{Result, VsockBackend, VsockError as Error, VSOCK_DEVICE_ID};

pub struct Vsock<M: GuestAddressSpace, B> {
    cfg: CommonConfig<M>,
    // Will likely be used in the future (i.e. when saving state).
    _cid: u64,
    backend: Option<B>,
}

impl<M, B> Vsock<M, B>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    B: VsockBackend + Send + 'static,
{
    pub fn new<Bus>(env: &mut Env<M, Bus>, cid: u64, backend: B) -> Result<Arc<Mutex<Self>>>
    where
        // We're using this (more convoluted) bound so we can pass both references and smart
        // pointers such as mutex guards here.
        Bus: DerefMut,
        Bus::Target: MmioManager<D = Arc<dyn DeviceMmio + Send + Sync>>,
    {
        // TODO: `VIRTIO_F_RING_EVENT_IDX` support is not negotiated in the initial iteration.
        // Add this as well in the next one.
        let device_features = (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_F_IN_ORDER);

        // An rx/tx queue pair. There's a 3rd queue for events as well, but it's not
        // supported during device operation for now.
        let queues = vec![Queue::new(env.mem.clone(), QUEUE_MAX_SIZE); 3];

        // Explicitly using `u64::from` here to ensure we're calling `to_le_bytes` on an `u64`.
        let config_space = u64::from(cid).to_le_bytes().to_vec();

        let virtio_cfg = VirtioConfig::new(device_features, queues, config_space);

        let common_cfg = CommonConfig::new(virtio_cfg, env).map_err(Error::Virtio)?;

        let vsock = Arc::new(Mutex::new(Vsock {
            cfg: common_cfg,
            _cid: cid,
            backend: Some(backend),
        }));

        env.register_mmio_device(vsock.clone())
            .map_err(Error::Virtio)?;

        Ok(vsock)
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static, B> VirtioDeviceType for Vsock<M, B> {
    fn device_type(&self) -> u32 {
        VSOCK_DEVICE_ID
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static, B> Borrow<VirtioConfig<M>> for Vsock<M, B> {
    fn borrow(&self) -> &VirtioConfig<M> {
        &self.cfg.virtio
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static, B> BorrowMut<VirtioConfig<M>> for Vsock<M, B> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<M> {
        &mut self.cfg.virtio
    }
}

impl<M, B> VirtioDeviceActions for Vsock<M, B>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    B: VsockBackend + 'static,
{
    type E = Error;

    fn activate(&mut self) -> Result<()> {
        let backend = self
            .backend
            .take()
            .ok_or(Error::Virtio(VirtioError::AlreadyActivated))?;

        let rxq = self.cfg.virtio.queues[0].clone();
        let txq = self.cfg.virtio.queues[1].clone();

        let driver_notify = SingleFdSignalQueue {
            irqfd: self.cfg.irqfd.clone(),
            interrupt_status: self.cfg.virtio.interrupt_status.clone(),
        };

        let inner = InOrderHandler {
            driver_notify,
            rxq,
            txq,
            backend,
        };

        let mut ioevents = self.cfg.prepare_activate().map_err(Error::Virtio)?;

        let handler = Arc::new(Mutex::new(QueueHandler {
            inner,
            rx_ioevent: ioevents.remove(0),
            tx_ioevent: ioevents.remove(0),
        }));

        self.cfg.finalize_activate(handler).map_err(Error::Virtio)
    }

    fn reset(&mut self) -> std::result::Result<(), Error> {
        // Not implemented for now.
        Ok(())
    }
}

impl<M, B> VirtioMmioDevice<M> for Vsock<M, B>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    B: VsockBackend + 'static,
{
}

impl<M, B> MutDeviceMmio for Vsock<M, B>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    B: VsockBackend + 'static,
{
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}
