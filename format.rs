use core::ptr;

use crate::addr::PhysAddr;
use crate::granule::{Level, TranslationGranule};
use crate::leaf::EncodedLeafAttrs;
use crate::table::{DescriptorKind, EncodedTableAttrs};

pub trait DescriptorFormat: Copy + Sized + 'static {
    type Raw: Copy + Eq;

    const DESCRIPTOR_BYTES: usize;

    const DESCRIPTOR_SHIFT: u8;

    const FINAL_LEVEL: Level = Level::L3;

    const BASE_LOWEST_ROOT_LEVEL: Level;

    const EXTENDED_LOWEST_ROOT_LEVEL: Level;

    const ADDRESS_FIELD_MASK: u128;

    const REQUIRED_FEATURES: RequiredFormatFeatures;

    fn invalid() -> Self::Raw;

    fn kind(raw: Self::Raw, level: Level) -> DescriptorKind;

    fn table_descriptor(table_pa: PhysAddr, attrs: EncodedTableAttrs<Self>) -> Self::Raw;

    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        attrs: EncodedLeafAttrs<Self>,
    ) -> Self::Raw;

    fn output_address<G: TranslationGranule>(raw: Self::Raw, level: Level) -> PhysAddr;

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw;

    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequiredFormatFeatures {
    pub lpa2: bool,
    pub d128: bool,
    pub extended_input_address: bool,
    pub extended_output_address: bool,
}

impl RequiredFormatFeatures {
    pub const NONE: Self = Self {
        lpa2: false,
        d128: false,
        extended_input_address: false,
        extended_output_address: false,
    };

    pub const D128: Self = Self {
        lpa2: false,
        d128: true,
        extended_input_address: false,
        extended_output_address: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredFeature {
    Lpa2,
    D128,
    ExtendedInputAddress,
    ExtendedOutputAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmsaV8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmsaV9;

const VMSA64_VALID: u64 = 1 << 0;
const VMSA64_TABLE_OR_PAGE: u64 = 1 << 1;
const VMSA64_TYPE_MASK: u64 = 0b11;

const VMSA64_ADDR_FIELD_MASK: u128 = 0x0000_FFFF_FFFF_F000;

const VMSA128_VALID: u128 = 1 << 0;

const VMSA128_LEVEL_DELTA_SHIFT: u8 = 1;
const VMSA128_LEVEL_DELTA_MASK: u128 = 0b11 << VMSA128_LEVEL_DELTA_SHIFT;

const VMSA128_ADDR_FIELD_MASK: u128 = 0x00FF_FFFF_FFFF_F000;

impl DescriptorFormat for VmsaV8 {
    type Raw = u64;

    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::L0;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const ADDRESS_FIELD_MASK: u128 = VMSA64_ADDR_FIELD_MASK;
    const REQUIRED_FEATURES: RequiredFormatFeatures = RequiredFormatFeatures::NONE;

    fn invalid() -> Self::Raw {
        0
    }

    fn kind(raw: Self::Raw, level: Level) -> DescriptorKind {
        match raw & VMSA64_TYPE_MASK {
            0b00 => DescriptorKind::Invalid,
            0b01 if level < Self::FINAL_LEVEL => DescriptorKind::Block,
            0b11 if level < Self::FINAL_LEVEL => DescriptorKind::Table,
            0b11 if level == Self::FINAL_LEVEL => DescriptorKind::Page,
            _ => DescriptorKind::Invalid,
        }
    }

    fn table_descriptor(table_pa: PhysAddr, attrs: EncodedTableAttrs<Self>) -> Self::Raw {
        ((table_pa.0 as u128 & Self::ADDRESS_FIELD_MASK) as u64)
            | attrs.bits()
            | VMSA64_VALID
            | VMSA64_TABLE_OR_PAGE
    }

    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        attrs: EncodedLeafAttrs<Self>,
    ) -> Self::Raw {
        let kind_bits = if level == Self::FINAL_LEVEL {
            VMSA64_VALID | VMSA64_TABLE_OR_PAGE
        } else {
            VMSA64_VALID
        };

        ((output_pa.0 as u128 & Self::ADDRESS_FIELD_MASK) as u64) | attrs.bits() | kind_bits
    }

    fn output_address<G: TranslationGranule>(raw: Self::Raw, level: Level) -> PhysAddr {
        let kind = Self::kind(raw, level);
        let mask = output_address_mask::<Self, G>(kind, level);

        PhysAddr((raw as u128 & mask) as u64)
    }

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        unsafe { ptr::read_volatile(ptr) }
    }

    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        unsafe {
            ptr::write_volatile(ptr, raw);
        }
    }
}

impl DescriptorFormat for VmsaV9 {
    type Raw = u128;

    const DESCRIPTOR_BYTES: usize = 16;
    const DESCRIPTOR_SHIFT: u8 = 4;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::NEG2;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG2;
    const ADDRESS_FIELD_MASK: u128 = VMSA128_ADDR_FIELD_MASK;
    const REQUIRED_FEATURES: RequiredFormatFeatures = RequiredFormatFeatures::D128;

    fn invalid() -> Self::Raw {
        0
    }

    fn kind(raw: Self::Raw, level: Level) -> DescriptorKind {
        if raw & VMSA128_VALID == 0 {
            return DescriptorKind::Invalid;
        }

        let resolved_level = Level::new(level.as_i8() + vmsa128_level_delta(raw));

        if resolved_level < Self::FINAL_LEVEL {
            DescriptorKind::Table
        } else if resolved_level == Self::FINAL_LEVEL {
            if level == Self::FINAL_LEVEL {
                DescriptorKind::Page
            } else {
                DescriptorKind::Block
            }
        } else {
            DescriptorKind::Invalid
        }
    }

    fn table_descriptor(table_pa: PhysAddr, attrs: EncodedTableAttrs<Self>) -> Self::Raw {
        ((table_pa.0 as u128) & Self::ADDRESS_FIELD_MASK)
            | attrs.bits()
            | VMSA128_VALID
            | vmsa128_level_delta_bits(0)
    }

    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        attrs: EncodedLeafAttrs<Self>,
    ) -> Self::Raw {
        let delta = Self::FINAL_LEVEL.as_i8() - level.as_i8();

        debug_assert!((0..=3).contains(&delta));

        ((output_pa.0 as u128) & Self::ADDRESS_FIELD_MASK)
            | attrs.bits()
            | VMSA128_VALID
            | vmsa128_level_delta_bits(delta as u8)
    }

    fn output_address<G: TranslationGranule>(raw: Self::Raw, level: Level) -> PhysAddr {
        let kind = Self::kind(raw, level);
        let mask = output_address_mask::<Self, G>(kind, level);

        PhysAddr((raw & mask) as u64)
    }

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        unsafe { ptr::read_volatile(ptr) }
    }

    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        unsafe {
            ptr::write_volatile(ptr, raw);
        }
    }
}

fn output_address_mask<F, G>(kind: DescriptorKind, level: Level) -> u128
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    let output_shift = match kind {
        DescriptorKind::Invalid => return 0,

        DescriptorKind::Table => G::SHIFT,

        DescriptorKind::Page => G::SHIFT,

        DescriptorKind::Block => level_output_shift::<F, G>(level),
    };

    F::ADDRESS_FIELD_MASK & !lower_bits_mask(output_shift)
}

fn level_output_shift<F, G>(level: Level) -> u8
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    let index_bits = G::SHIFT - F::DESCRIPTOR_SHIFT;
    let level_delta = F::FINAL_LEVEL.as_i8() - level.as_i8();

    if level_delta <= 0 {
        return G::SHIFT;
    }

    G::SHIFT + index_bits * (level_delta as u8)
}

fn vmsa128_level_delta(raw: u128) -> i8 {
    ((raw & VMSA128_LEVEL_DELTA_MASK) >> VMSA128_LEVEL_DELTA_SHIFT) as i8
}

fn vmsa128_level_delta_bits(delta: u8) -> u128 {
    debug_assert!(delta <= 3);

    ((delta as u128) << VMSA128_LEVEL_DELTA_SHIFT) & VMSA128_LEVEL_DELTA_MASK
}

const fn lower_bits_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}
