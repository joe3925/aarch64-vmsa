use crate::address::VirtAddr;
use crate::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};

pub use paging::address::{GranuleError, Level, TranslationGranule};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GranuleKind {
    Size4KiB,
    Size16KiB,
    Size64KiB,
}

impl GranuleKind {
    pub const fn shift(self) -> u8 {
        match self {
            Self::Size4KiB => 12,
            Self::Size16KiB => 14,
            Self::Size64KiB => 16,
        }
    }
    pub const fn size(self) -> u64 {
        1u64 << self.shift()
    }
    pub const fn mask(self) -> u64 {
        self.size() - 1
    }
    pub const fn page_offset(self, va: VirtAddr) -> u64 {
        va.0 & self.mask()
    }
    pub const fn is_page_aligned(self, value: u64) -> bool {
        value & self.mask() == 0
    }
    pub const fn align_down(self, value: u64) -> u64 {
        value & !self.mask()
    }
    pub fn align_up(self, value: u64) -> Option<u64> {
        value
            .checked_add(self.mask())
            .map(|value| value & !self.mask())
    }
    pub const fn validate_page_alignment(self, value: u64) -> Result<(), GranuleError> {
        if self.is_page_aligned(value) {
            Ok(())
        } else {
            Err(GranuleError::AddressNotAligned)
        }
    }
}

pub trait ArmTranslationGranule: TranslationGranule {
    const KIND: GranuleKind;
    fn kind() -> GranuleKind {
        Self::KIND
    }
}

unsafe impl TranslationGranule for Granule4KiB {
    const SHIFT: u8 = 12;
}
unsafe impl TranslationGranule for Granule16KiB {
    const SHIFT: u8 = 14;
}
unsafe impl TranslationGranule for Granule64KiB {
    const SHIFT: u8 = 16;
}
impl<G: TranslationGranule> ArmTranslationGranule for G {
    const KIND: GranuleKind = match G::SHIFT {
        12 => GranuleKind::Size4KiB,
        14 => GranuleKind::Size16KiB,
        16 => GranuleKind::Size64KiB,
        _ => panic!("unsupported Arm translation granule"),
    };
}
