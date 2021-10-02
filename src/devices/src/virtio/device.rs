//! This module defines intermediate level abstractions for Virtio device implementations.
//! They are not fully generic in the sense that we assume certain assumptions about the
//! environment (i.e. we are using KVM, EventFds, and a couple of other things), but otherwise
//! we are tying to identify and consolidate as much common functionality as possible, to
//! to simplify the definition, testing, and maintenance of multiple specific Virtio device
//! implementations.
//!
//! In turn, the logic here leverages higher-level functionality from rust-vmm (such as things
//! from the virtio workspaces), with aim of creating a layered stack of abstractions, such that
//! different use cases can identify and reuse as much as possible depending on the particular
//! assumptions that apply.

// We consolidate here as much of the common device logic as possible, and delegate the rest
// to particular implementations via the `RefVirtioDeviceT` trait. One important thing that's
// not currently present is state save/restore, but we're going to add that as well.

use std::borrow::{Borrow, BorrowMut};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::result::Result;
use std::sync::{Arc, Mutex};

use event_manager::{RemoteEndpoint, SubscriberId};
use kvm_ioctls::{IoEventAddress, VmFd};
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::Queue;
use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vm_memory::{GuestAddress, GuestAddressSpace};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use super::env::MmioEnvironment;
use super::features;
use super::{
    Error, MmioConfig, SingleFdSignalQueue, Subscriber, QUEUE_MAX_SIZE,
    VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET,
};

/// Defines operations that are specific to particular Virtio device implementations.
pub trait RefVirtioDeviceT {
    /// The error type that can be returned by the following methods.
    type E: Debug + From<Error>;

    /// Return the Virtio device type.
    fn device_type(&self) -> u32;

    /// Return any additional parameters for the guest kernel command line that are required
    /// by specific devices to operate (i.e. not including something like kernel cmdline parameters
    /// used for generic Virtio over MMIO device discovery).
    fn cmdline_str(&self) -> Option<String>;

    /// Return the set of features enabled by the device.
    fn features(&self) -> u64;

    /// Return the number of queues used by the device.
    // TODO: We may need a better abstraction here when we start dealing with devices that have
    // a configurable number of queues.
    fn num_queues(&self) -> usize;

    /// Return the contents of the device configuration space.
    fn config_space(&self) -> Result<Vec<u8>, Self::E>;

    /// Run device-specific activation logic.
    // TODO: Going forward, we'll likely want to have a generic type parameter for `s`, since
    // using the same implementation might not be optimal for different use cases such as
    // PCI vs MMIO transports.
    fn activate<M: GuestAddressSpace + Send + 'static>(
        &mut self,
        s: SingleFdSignalQueue,
        queues: Vec<(Queue<M>, EventFd)>,
        driver_features: u64,
    ) -> Result<Subscriber, Self::E>;
}

/// Represents a Virtio device as defined for this particular implementation and set of
/// assumptions. Different `inner` backends are used to offer the functionality associated
/// with various specific devices (i.e. block, net, etc.)
// The current implementation is MMIO-specific for now; we'll extend it to support the PCI
// transport as well in the future.
pub struct RefVirtioDevice<M: GuestAddressSpace, D> {
    virtio_cfg: VirtioConfig<M>,
    mmio_cfg: MmioConfig,
    endpoint: RemoteEndpoint<Subscriber>,
    vm_fd: Arc<VmFd>,
    irqfd: Arc<EventFd>,
    inner: D,
}

impl<M, D> RefVirtioDevice<M, D>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    D: RefVirtioDeviceT + Send + 'static,
{
    /// Create a new device and register it with the MMIO manager.
    pub fn new_arc<E: MmioEnvironment<M = M>>(
        env: &mut E,
        inner: D,
    ) -> Result<Arc<Mutex<Self>>, D::E> {
        let device_features = inner.features();

        let queues = vec![Queue::new(env.mem(), QUEUE_MAX_SIZE); inner.num_queues()];

        let config_space = inner.config_space()?;

        let virtio_cfg = VirtioConfig::new(device_features, queues, config_space);

        let mmio_cfg = MmioConfig {
            gsi: env.req_gsi(None)?,
            range: env.req_mmio_range(None, 0x1000)?,
        };

        let vm_fd = env.vm_fd();

        let irqfd = Arc::new(EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?);
        vm_fd
            .register_irqfd(&irqfd, mmio_cfg.gsi)
            .map_err(Error::RegisterIrqfd)?;

        env.kernel_cmdline()
            .add_virtio_mmio_device(
                mmio_cfg.range.size(),
                GuestAddress(mmio_cfg.range.base().0),
                mmio_cfg.gsi,
                None,
            )
            .map_err(Error::Cmdline)?;

        if let Some(s) = inner.cmdline_str() {
            env.kernel_cmdline().insert_str(s).map_err(Error::Cmdline)?;
        }

        let device = Arc::new(Mutex::new(Self {
            virtio_cfg,
            mmio_cfg,
            endpoint: env.remote_endpoint(),
            vm_fd,
            irqfd,
            inner,
        }));

        env.register_mmio_device(mmio_cfg.range, device.clone())?;

        Ok(device)
    }
}

impl<M, D> VirtioDeviceType for RefVirtioDevice<M, D>
where
    M: GuestAddressSpace + Clone + Send,
    D: RefVirtioDeviceT,
{
    fn device_type(&self) -> u32 {
        self.inner.device_type()
    }
}

impl<M, D> Borrow<VirtioConfig<M>> for RefVirtioDevice<M, D>
where
    M: GuestAddressSpace + Clone + Send,
    D: RefVirtioDeviceT,
{
    fn borrow(&self) -> &VirtioConfig<M> {
        &self.virtio_cfg
    }
}

impl<M, D> BorrowMut<VirtioConfig<M>> for RefVirtioDevice<M, D>
where
    M: GuestAddressSpace + Clone + Send,
    D: RefVirtioDeviceT,
{
    fn borrow_mut(&mut self) -> &mut VirtioConfig<M> {
        &mut self.virtio_cfg
    }
}

impl<M, D> VirtioDeviceActions for RefVirtioDevice<M, D>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    D: RefVirtioDeviceT,
{
    type E = D::E;

    // This is the implementation of the `VirtioDeviceActions::activate` method from upstream
    // `virtio-device`, which begins by performing logic which is common to all devices, and
    // then calls `inner.activate()` for device-specific functionality. The current contract
    // is that `inner.activate()` returns a subscriber which we the register with the event
    // manager from the environment, which is responsible for handling device-specific events.
    // We'll implement the necessary changes/additions to cover nuances required by state
    // save/restore and multi-threaded event handling as required moving forward.
    fn activate(&mut self) -> Result<(), Self::E> {
        if !self.virtio_cfg.queues_valid() {
            return Err(Error::QueuesNotValid.into());
        }

        if self.virtio_cfg.device_activated {
            return Err(Error::AlreadyActivated.into());
        }

        // We do not support legacy drivers.
        if self.virtio_cfg.driver_features & (1 << features::VIRTIO_F_VERSION_1) == 0 {
            return Err(Error::BadFeatures(self.virtio_cfg.driver_features).into());
        }

        let queues = self.virtio_cfg.queues.clone();

        let driver_notify = SingleFdSignalQueue {
            irqfd: self.irqfd.clone(),
            interrupt_status: self.virtio_cfg.interrupt_status.clone(),
        };

        let mut ioevents = Vec::new();

        // Right now, we operate under the assumption all queues are marked ready by the device
        // (which is true until we start supporting devices that can optionally make use of
        // additional queues on top of the defaults).
        for i in 0..queues.len() {
            let fd = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;

            // Register the queue event fd.
            self.vm_fd
                .register_ioevent(
                    &fd,
                    &IoEventAddress::Mmio(
                        self.mmio_cfg.range.base().0 + VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET,
                    ),
                    // The maximum number of queues should fit within an `u16` according to the
                    // standard, so the conversion below is always expected to succeed.
                    u32::try_from(i).unwrap(),
                )
                .map_err(Error::RegisterIoevent)?;

            ioevents.push(fd);
        }

        let v = queues.into_iter().zip(ioevents.into_iter()).collect();

        let handler = self
            .inner
            .activate(driver_notify, v, self.virtio_cfg.driver_features)?;

        // Register the queue handler with the `EventManager`. We could record the `sub_id`
        // (and/or keep a handler clone) for further interaction (i.e. to remove the subscriber at
        // a later time, retrieve state, etc).
        let _sub_id = self
            .endpoint
            .call_blocking(move |mgr| -> event_manager::Result<SubscriberId> {
                Ok(mgr.add_subscriber(handler))
            })
            .map_err(Error::Endpoint)?;

        self.virtio_cfg.device_activated = true;

        Ok(())
    }

    fn reset(&mut self) -> Result<(), Self::E> {
        // Not implemented for now.
        Ok(())
    }
}

impl<M, D> VirtioMmioDevice<M> for RefVirtioDevice<M, D>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    D: RefVirtioDeviceT,
{
}

impl<M, D> MutDeviceMmio for RefVirtioDevice<M, D>
where
    M: GuestAddressSpace + Clone + Send + 'static,
    D: RefVirtioDeviceT,
{
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}
