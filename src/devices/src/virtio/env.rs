use std::sync::Arc;

use event_manager::RemoteEndpoint;
use kvm_ioctls::VmFd;
use linux_loader::cmdline::Cmdline;
use vm_device::bus::{MmioAddress, MmioRange};
use vm_device::DeviceMmio;

use super::{Result, Subscriber};

// We want to have interfaces that clearly separate devices from the VMMs that use them, such that
// any device can be used in a VMM that meets certain criteria, without any hard coupling between
// the two. The traits present in this module present one way to abstract away the requirements
// devices implemented by this crate demand from the environment where they are used. The mode of
// operation is devices get a suitable environment handle, perform the appropriate setup, and
// become active based on later interaction with the guest (i.e. Virtio discovery, configuration,
// and activation). The abstractions are mostly about Virtio over MMIO for now, but can be
// extended to support the Virtio over PCI transport later.

/// The `Environment` trait stands for a set of operations that Virtio devices in this crate
/// expect to perform on the VMM/context where they are added to perform their initial setup.
pub trait Environment {
    /// Stands for the memory abstraction used by the environment.
    type M;

    /// Return an object is used to interact with the memory of the guest.
    // TODO: We'll prob want to return a reference here vs. an owned object, but we'll need some
    // adjustments/changes in upstream `vm-memory` first.
    fn mem(&self) -> Self::M;

    /// Return a handle to the `VmFd` object for the underlying KVM vm.
    fn vm_fd(&self) -> Arc<VmFd>;

    /// Request a `gsi` number from the environment. The `specific` argument can be used to
    /// demand a specific value (or an error when that's not available). When `specific` is
    /// `None` we'll just get the next available value.
    fn req_gsi(&mut self, specific: Option<u32>) -> Result<u32>;

    /// Return a `RemoteEndpoint` object associated with the `EventManager` the device will
    /// will register to.
    // TODO: We'll likely have to adjust the interface when supporting multiple event loops
    // (i.e. for multiple service threads).
    fn remote_endpoint(&self) -> RemoteEndpoint<Subscriber>;

    /// Return a mutable handle to the `Cmdline` that's subsequently passed to the
    /// guest kernel at boot.
    fn kernel_cmdline(&mut self) -> &mut Cmdline;
}

/// Represents an `Environment` which exposes some additional operations required by devices
/// using the Virtio over MMIO transport.
pub trait MmioEnvironment: Environment {
    /// Request a (potentially specific) MMIO range to be allocated for use by the device.
    fn req_mmio_range(&mut self, base: Option<MmioAddress>, size: u64) -> Result<MmioRange>;

    /// Register a `DeviceMmio` trait object with the device manger present in the environment.
    fn register_mmio_device(
        &mut self,
        range: MmioRange,
        device: Arc<dyn DeviceMmio + Sync + Send>,
    ) -> Result<()>;
}
