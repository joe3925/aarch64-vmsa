pub mod walk {
    pub use paging::translation::walk::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum CanonicalWalkInputAddrError {
        InvalidAddressBits { addr_bits: u8 },
        NotCanonical { addr: u64, addr_bits: u8 },
    }

    pub const fn from_canonical(
        raw: u64,
        addr_bits: u8,
    ) -> Result<WalkInputAddr, CanonicalWalkInputAddrError> {
        if addr_bits == 0 || addr_bits > u64::BITS as u8 {
            return Err(CanonicalWalkInputAddrError::InvalidAddressBits { addr_bits });
        }
        if addr_bits == u64::BITS as u8 {
            return Ok(WalkInputAddr::new(raw));
        }
        let mask = (1u64 << addr_bits) - 1;
        let upper = raw & !mask;
        if upper != 0 && upper != !mask {
            return Err(CanonicalWalkInputAddrError::NotCanonical {
                addr: raw,
                addr_bits,
            });
        }
        Ok(WalkInputAddr::new(raw & mask))
    }
}

pub use walk::*;

mod private {
    pub trait Sealed {}
}
pub trait TranslationStage: private::Sealed + Copy + 'static {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2;
impl private::Sealed for Stage1 {}
impl private::Sealed for Stage2 {}
impl TranslationStage for Stage1 {}
impl TranslationStage for Stage2 {}
