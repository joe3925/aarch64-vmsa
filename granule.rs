use crate::addr::VirtAddr;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Level(i8);

impl Level {
    pub const NEG2: Self = Self(-2);
    pub const NEG1: Self = Self(-1);
    pub const L0: Self = Self(0);
    pub const L1: Self = Self(1);
    pub const L2: Self = Self(2);
    pub const L3: Self = Self(3);

    pub const fn new(value: i8) -> Self {
        Self(value)
    }

    pub const fn as_i8(self) -> i8 {
        self.0
    }

    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    pub const fn previous(self) -> Self {
        Self(self.0 - 1)
    }

    pub const fn is_l0(self) -> bool {
        self.0 == Self::L0.0
    }

    pub const fn is_l1(self) -> bool {
        self.0 == Self::L1.0
    }

    pub const fn is_l2(self) -> bool {
        self.0 == Self::L2.0
    }

    pub const fn is_l3(self) -> bool {
        self.0 == Self::L3.0
    }

    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }

    pub const fn is_before(self, other: Self) -> bool {
        self.0 < other.0
    }

    pub const fn is_after(self, other: Self) -> bool {
        self.0 > other.0
    }

    pub const fn is_between_inclusive(self, start: Self, end: Self) -> bool {
        self.0 >= start.0 && self.0 <= end.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GranuleError {
    AddressNotAligned,
}

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
        value.checked_add(self.mask()).map(|v| v & !self.mask())
    }

    pub const fn validate_page_alignment(self, value: u64) -> Result<(), GranuleError> {
        if self.is_page_aligned(value) {
            Ok(())
        } else {
            Err(GranuleError::AddressNotAligned)
        }
    }
}

pub trait TranslationGranule: Copy + 'static {
    const KIND: GranuleKind;
    const SHIFT: u8;
    const SIZE: u64 = 1u64 << Self::SHIFT;
    const MASK: u64 = Self::SIZE - 1;

    fn kind() -> GranuleKind {
        Self::KIND
    }

    fn shift() -> u8 {
        Self::SHIFT
    }

    fn size() -> u64 {
        Self::SIZE
    }

    fn mask() -> u64 {
        Self::MASK
    }

    fn page_offset(va: VirtAddr) -> u64 {
        va.0 & Self::MASK
    }

    fn is_page_aligned(value: u64) -> bool {
        value & Self::MASK == 0
    }

    fn align_down(value: u64) -> u64 {
        value & !Self::MASK
    }

    fn align_up(value: u64) -> Option<u64> {
        value.checked_add(Self::MASK).map(|v| v & !Self::MASK)
    }

    fn validate_page_alignment(value: u64) -> Result<(), GranuleError> {
        if Self::is_page_aligned(value) {
            Ok(())
        } else {
            Err(GranuleError::AddressNotAligned)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Granule4KiB;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Granule16KiB;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Granule64KiB;

impl TranslationGranule for Granule4KiB {
    const KIND: GranuleKind = GranuleKind::Size4KiB;
    const SHIFT: u8 = 12;
}

impl TranslationGranule for Granule16KiB {
    const KIND: GranuleKind = GranuleKind::Size16KiB;
    const SHIFT: u8 = 14;
}

impl TranslationGranule for Granule64KiB {
    const KIND: GranuleKind = GranuleKind::Size64KiB;
    const SHIFT: u8 = 16;
}

pub const fn div_ceil_u8(value: u8, divisor: u8) -> u8 {
    value / divisor + ((value % divisor) != 0) as u8
}
