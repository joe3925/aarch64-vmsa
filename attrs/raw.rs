use super::AttrError;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FourBit(u8);

impl FourBit {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u8) -> Result<Self, AttrError> {
        if value <= 0xf {
            Ok(Self(value))
        } else {
            Err(AttrError::RawFieldOutOfRange)
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_masked(value: u128) -> Self {
        Self((value & 0xf) as u8)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ThreeBit(u8);

impl ThreeBit {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u8) -> Result<Self, AttrError> {
        if value <= 0x7 {
            Ok(Self(value))
        } else {
            Err(AttrError::RawFieldOutOfRange)
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_masked(value: u128) -> Self {
        Self((value & 0x7) as u8)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TenBit(u16);

impl TenBit {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u16) -> Result<Self, AttrError> {
        if value <= 0x3ff {
            Ok(Self(value))
        } else {
            Err(AttrError::RawFieldOutOfRange)
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub(crate) const fn from_masked(value: u128) -> Self {
        Self((value & 0x3ff) as u16)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LeafAp(u8);

impl LeafAp {
    pub const fn from_bits(bits: u8) -> Result<Self, AttrError> {
        if bits <= 0b11 {
            Ok(Self(bits))
        } else {
            Err(AttrError::RawFieldOutOfRange)
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_masked(bits: u128) -> Self {
        Self((bits & 0b11) as u8)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TableAp(u8);

impl TableAp {
    pub const fn from_bits(bits: u8) -> Result<Self, AttrError> {
        if bits <= 0b11 {
            Ok(Self(bits))
        } else {
            Err(AttrError::RawFieldOutOfRange)
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_masked(bits: u128) -> Self {
        Self((bits & 0b11) as u8)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Stage2Ap(u8);

impl Stage2Ap {
    pub const fn from_bits(bits: u8) -> Result<Self, AttrError> {
        if bits <= 0b11 {
            Ok(Self(bits))
        } else {
            Err(AttrError::RawFieldOutOfRange)
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_masked(bits: u128) -> Self {
        Self((bits & 0b11) as u8)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Stage2ExecuteNever(u8);

impl Stage2ExecuteNever {
    pub const fn from_bits(bits: u8) -> Result<Self, AttrError> {
        if bits <= 0b11 {
            Ok(Self(bits))
        } else {
            Err(AttrError::RawFieldOutOfRange)
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_masked(bits: u128) -> Self {
        Self((bits & 0b11) as u8)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RawShareability(u8);

impl RawShareability {
    pub const fn from_bits(bits: u8) -> Result<Self, AttrError> {
        match bits {
            0b00 | 0b10 | 0b11 => Ok(Self(bits)),
            _ => Err(AttrError::InvalidShareability),
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_masked(bits: u128) -> Self {
        Self((bits & 0b11) as u8)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Stage1NotDirty(bool);

impl Stage1NotDirty {
    pub const fn new(value: bool) -> Self {
        Self(value)
    }

    pub const fn bit(self) -> bool {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Stage2Dirty(bool);

impl Stage2Dirty {
    pub const fn new(value: bool) -> Self {
        Self(value)
    }

    pub const fn bit(self) -> bool {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionIndices {
    pub pi: FourBit,
    pub po: FourBit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawVmsa64Stage1LeafAttrs {
    pub attr_index: ThreeBit,
    pub ns: bool,
    pub ap: LeafAp,
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub alias_bit: bool,
    pub dirty_bit_modifier: bool,
    pub contiguous: bool,
    pub privileged_execute_never: bool,
    pub unprivileged_execute_never: bool,
    pub guarded: bool,
    pub software: FourBit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawVmsa64Stage1TableAttrs {
    pub privileged_execute_never_limit: bool,
    pub unprivileged_execute_never_limit: bool,
    pub ap_table: TableAp,
    pub ns_table: bool,
    pub software: FourBit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawVmsa64Stage2LeafAttrs {
    pub mem_attr: FourBit,
    pub access: Stage2Ap,
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub dirty_bit_modifier: bool,
    pub contiguous: bool,
    pub execute_never: Stage2ExecuteNever,
    pub software: FourBit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawVmsa64Stage2TableAttrs {
    pub software: FourBit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawVmsa128Stage1LeafAttrs {
    pub attr_index: FourBit,
    pub bbm_nt: bool,
    pub not_dirty: Stage1NotDirty,
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub alias_bit: bool,
    pub contiguous: bool,
    pub guarded: bool,
    pub protected: bool,
    pub permissions: PermissionIndices,
    pub ns: bool,
    pub software: TenBit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawVmsa128Stage1TableAttrs {
    pub table_nt: bool,
    pub access_flag: bool,
    pub disch: bool,
    pub protected: bool,
    pub ns_table: bool,
    pub software: TenBit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawVmsa128Stage2LeafAttrs {
    pub mem_attr: FourBit,
    pub bbm_nt: bool,
    pub dirty: Stage2Dirty,
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub force_no_execute: bool,
    pub contiguous: bool,
    pub assured_only: bool,
    pub permissions: PermissionIndices,
    pub ns: bool,
    pub software: TenBit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawVmsa128Stage2TableAttrs {
    pub table_nt: bool,
    pub access_flag: bool,
    pub software: TenBit,
}
