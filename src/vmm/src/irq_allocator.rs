use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// An irq allocator which gives next available irq.
/// It is mainly used for non-legacy devices.
// There are a few reserved irq's on x86_64. We just skip all the inital
// reserved irq to make the implementaion simple. This could be later extended
// to cater more complex scenario.
#[derive(Debug)]
pub struct IrqAllocator {
    // Tracks the last allocated irq
    last_used_irq: u32,
    max: u32,
}

impl IrqAllocator {
    pub fn new(last_used_irq: u32, max: u32) -> Result<Self> {
        if last_used_irq >= max {
            return Err(Error::InvalidValue);
        }
        Ok(IrqAllocator { last_used_irq, max })
    }

    pub fn next_irq(&mut self) -> Result<u32> {
        match self.last_used_irq.checked_add(1) {
            Some(irq) => {
                if irq > self.max {
                    return Err(Error::MaxIrq);
                }
                self.last_used_irq = irq;
                Ok(irq)
            }
            // This condition will never be reached because
            // last_used_irq is always less than max. So we can't have
            // u32::MAX as last_used_irq and max value.
            None => Err(Error::IRQOverflowed),
        }
    }
}
#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidValue,
    MaxIrq,
    IRQOverflowed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let err = match self {
            Error::MaxIrq => "Max IRQ limit reached",
            Error::IRQOverflowed => "IRQ overflowed",
            Error::InvalidValue => {
                "Check the value of last_used and max. las_used should be less than max"
            }
        };
        write!(f, "{}", err) // user-facing output
    }
}

#[cfg(test)]
mod test {
    use super::{Error, IrqAllocator};
    #[test]
    fn test_new() {
        let irq_alloc = IrqAllocator::new(4, 10).unwrap();
        assert_eq!(irq_alloc.last_used_irq, 4);
        assert_eq!(irq_alloc.max, 10);
        let irq_alloc = IrqAllocator::new(4, 4).unwrap_err();
        assert_eq!(irq_alloc, Error::InvalidValue);
        let irq_alloc = IrqAllocator::new(4, 3).unwrap_err();
        assert_eq!(irq_alloc, Error::InvalidValue);
    }
    #[test]
    fn test_next_irq() {
        let mut irq_alloc = IrqAllocator::new(4, 7).unwrap();
        assert_eq!(irq_alloc.next_irq(), Ok(5));

        let _ = irq_alloc.next_irq();
        assert_eq!(irq_alloc.next_irq(), Ok(7));

        assert_eq!(irq_alloc.next_irq(), Err(Error::MaxIrq));
    }
}
