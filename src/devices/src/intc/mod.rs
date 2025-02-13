use kvm_ioctls::VmFd;
use std::io;
use std::sync::Arc;
use vm_superio::Trigger;

#[derive(Clone)]
pub struct APlicTrigger {
    pub gsi: u32,
    pub vm: Arc<VmFd>,
}

impl APlicTrigger {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(APlicTrigger {
            gsi: self.gsi,
            vm: self.vm.clone(),
        })
    }
}

impl Trigger for APlicTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        self.vm.set_irq_line(self.gsi, true)?;
        self.vm.set_irq_line(self.gsi, false)?;

        Ok(())
    }
}
