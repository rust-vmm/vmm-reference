mod serial;
pub use serial::SerialWrapper;
pub use serial::Error as SerialError;

use std::io;
use std::ops::Deref;

use vm_superio::Trigger;
use vmm_sys_util::eventfd::EventFd;

/// Newtype for implementing the trigger functionality for `EventFd`.
///
/// The trigger is used for handling events in the legacy devices.
pub struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        self.write(1)
    }
}
impl Deref for EventFdTrigger {
    type Target = EventFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl EventFdTrigger {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }
    pub fn new(flag: i32) -> io::Result<Self> {
        let event_fd = EventFd::new(flag)?;
        Ok(EventFdTrigger(event_fd))
    }
}