mod vmsa128;
mod vmsa64;
mod vmsa64_family;
mod vmsa64_lpa2;

#[cfg(target_has_atomic = "64")]
use portable_atomic::AtomicU64;
#[cfg(all(target_has_atomic = "64", not(target_has_atomic = "128")))]
use portable_atomic::Ordering;
#[cfg(target_has_atomic = "128")]
use portable_atomic::{AtomicU128, Ordering};

use crate::address::{Level, PhysAddr, TranslationGranule};
use crate::arch::FeatureRequirements;
use crate::config::format::{Vmsa64, Vmsa64Lpa2, Vmsa128};
use crate::table::{TableAddr, TableTransition};
use crate::translation::TranslationStage;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorKind {
    Block,
    Page,
    Table,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NextTableDescriptor<G>
where
    G: TranslationGranule,
{
    pub address: TableAddr<G>,
    pub level: Level,
    pub stride_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    InvalidLeafLevel {
        level: Level,
    },
    InvalidTableTransition {
        parent_level: Level,
        child_level: Level,
        stride_count: u8,
    },
    ReservedFieldSet {
        bit: u8,
    },
    InvalidNtBbmCombination {
        level: Level,
    },
    InvalidReservedBitState,
}

mod private {
    pub trait FormatSealed {}
    pub trait LayoutSealed {}
}

pub trait DescriptorFormat: private::FormatSealed + Copy + Sized + 'static {
    type Raw: Copy + Eq;

    const DESCRIPTOR_BYTES: usize;
    const DESCRIPTOR_SHIFT: u8;
    const OUTPUT_ADDRESS_BITS: u8;
    const FINAL_LEVEL: Level = Level::L3;
    const BASE_LOWEST_ROOT_LEVEL: Level;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level;
    const REQUIRED_FEATURES: FeatureRequirements;

    fn invalid() -> Self::Raw;
    fn supports_leaf_level<G: TranslationGranule>(level: Level) -> bool;

    /// Reads one descriptor.
    ///
    /// # Safety
    /// `ptr` must be aligned and valid for one initialized descriptor.
    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw;

    /// Writes one descriptor.
    ///
    /// # Safety
    /// `ptr` must be aligned and valid for one writable descriptor.
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw);
}

/// Marks a format that supports atomic access to live descriptors.
pub trait SupportsLiveDescriptorIo: DescriptorFormat {}

pub trait DescriptorLayout<S, G>: private::LayoutSealed + Copy + 'static
where
    S: TranslationStage,
    G: TranslationGranule,
{
    type Format: DescriptorFormat;
    type LeafFields: Copy;
    type TableFields: Copy;

    const REQUIRED_FEATURES: FeatureRequirements = Self::Format::REQUIRED_FEATURES;
    const ADDRESS_FIELD_MASK: u128;

    fn kind(raw: <Self::Format as DescriptorFormat>::Raw, level: Level) -> DescriptorKind;
    fn decode_leaf_fields(
        raw: <Self::Format as DescriptorFormat>::Raw,
        level: Level,
    ) -> Self::LeafFields;
    fn decode_table_fields(
        raw: <Self::Format as DescriptorFormat>::Raw,
        level: Level,
    ) -> Self::TableFields;
    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        fields: Self::LeafFields,
    ) -> Result<<Self::Format as DescriptorFormat>::Raw, DescriptorError>;
    fn table_descriptor(
        table_addr: TableAddr<G>,
        transition: TableTransition<Self::Format, G>,
        fields: Self::TableFields,
    ) -> Result<<Self::Format as DescriptorFormat>::Raw, DescriptorError>;
    fn output_address(raw: <Self::Format as DescriptorFormat>::Raw, level: Level) -> PhysAddr;

    fn table_address(raw: <Self::Format as DescriptorFormat>::Raw, level: Level) -> TableAddr<G> {
        let raw = Self::output_address(raw, level).0;
        // SAFETY: Descriptor address fields do not contain granule-offset bits.
        unsafe { TableAddr::new_unchecked(raw) }
    }

    fn next_table(
        raw: <Self::Format as DescriptorFormat>::Raw,
        level: Level,
    ) -> Option<NextTableDescriptor<G>> {
        level
            .is_before(Self::Format::FINAL_LEVEL)
            .then(|| NextTableDescriptor {
                address: Self::table_address(raw, level),
                level: level.next(),
                stride_count: 1,
            })
    }

    fn supports_table_transition(transition: TableTransition<Self::Format, G>) -> bool {
        transition.level_step() == 1 && transition.child().stride_count().raw() == 1
    }
}

pub trait HasLayout<S, G>: DescriptorFormat
where
    S: TranslationStage,
    G: TranslationGranule,
{
    type Layout: DescriptorLayout<S, G, Format = Self>;
}

impl private::FormatSealed for Vmsa64 {}
impl private::FormatSealed for Vmsa64Lpa2 {}
impl private::FormatSealed for Vmsa128 {}

#[cfg(target_has_atomic = "64")]
impl SupportsLiveDescriptorIo for Vmsa64 {}
#[cfg(target_has_atomic = "64")]
impl SupportsLiveDescriptorIo for Vmsa64Lpa2 {}
#[cfg(target_has_atomic = "128")]
impl SupportsLiveDescriptorIo for Vmsa128 {}

impl DescriptorFormat for Vmsa64 {
    type Raw = u64;
    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const OUTPUT_ADDRESS_BITS: u8 = 48;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::L0;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;

    fn invalid() -> Self::Raw {
        0
    }
    fn supports_leaf_level<G: TranslationGranule>(level: Level) -> bool {
        vmsa64::supports_leaf_level(G::KIND, level)
    }
    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller supplies an aligned, readable descriptor pointer.
            unsafe { AtomicU64::from_ptr(ptr.cast_mut()).load(Ordering::Acquire) }
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller supplies an aligned, readable descriptor pointer.
            unsafe { core::ptr::read_volatile(ptr) }
        }
    }
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller supplies an aligned, writable descriptor pointer.
            unsafe { AtomicU64::from_ptr(ptr).store(raw, Ordering::Release) }
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller supplies an aligned, writable descriptor pointer.
            unsafe { core::ptr::write_volatile(ptr, raw) }
        }
    }
}

impl DescriptorFormat for Vmsa64Lpa2 {
    type Raw = u64;
    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const OUTPUT_ADDRESS_BITS: u8 = 52;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .with_lpa2()
        .with_extended_output_address();

    fn invalid() -> Self::Raw {
        0
    }
    fn supports_leaf_level<G: TranslationGranule>(level: Level) -> bool {
        vmsa64_lpa2::supports_leaf_level(G::KIND, level)
    }
    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller supplies an aligned, readable descriptor pointer.
            unsafe { AtomicU64::from_ptr(ptr.cast_mut()).load(Ordering::Acquire) }
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller supplies an aligned, readable descriptor pointer.
            unsafe { core::ptr::read_volatile(ptr) }
        }
    }
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller supplies an aligned, writable descriptor pointer.
            unsafe { AtomicU64::from_ptr(ptr).store(raw, Ordering::Release) }
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller supplies an aligned, writable descriptor pointer.
            unsafe { core::ptr::write_volatile(ptr, raw) }
        }
    }
}

impl DescriptorFormat for Vmsa128 {
    type Raw = u128;
    const DESCRIPTOR_BYTES: usize = 16;
    const DESCRIPTOR_SHIFT: u8 = 4;
    const OUTPUT_ADDRESS_BITS: u8 = 56;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::NEG2;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG2;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE.with_d128();

    fn invalid() -> Self::Raw {
        0
    }
    fn supports_leaf_level<G: TranslationGranule>(level: Level) -> bool {
        vmsa128::supports_leaf_level(G::KIND, level)
    }
    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        #[cfg(target_has_atomic = "128")]
        {
            // SAFETY: The caller supplies an aligned, readable descriptor pointer.
            unsafe { AtomicU128::from_ptr(ptr.cast_mut()).load(Ordering::Acquire) }
        }
        #[cfg(not(target_has_atomic = "128"))]
        {
            // SAFETY: The caller supplies an aligned, readable descriptor pointer.
            unsafe { core::ptr::read_volatile(ptr) }
        }
    }
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        #[cfg(target_has_atomic = "128")]
        {
            // SAFETY: The caller supplies an aligned, writable descriptor pointer.
            unsafe { AtomicU128::from_ptr(ptr).store(raw, Ordering::Release) }
        }
        #[cfg(not(target_has_atomic = "128"))]
        {
            // SAFETY: The caller supplies an aligned, writable descriptor pointer.
            unsafe { core::ptr::write_volatile(ptr, raw) }
        }
    }
}

pub(crate) fn require_step_by_one_transition<F, G>(
    transition: TableTransition<F, G>,
) -> Result<(), DescriptorError>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    if transition.level_step() == 1 && transition.child().stride_count().raw() == 1 {
        Ok(())
    } else {
        Err(DescriptorError::InvalidTableTransition {
            parent_level: transition.parent_level(),
            child_level: transition.child_level(),
            stride_count: transition.child().stride_count().raw(),
        })
    }
}

pub(crate) const fn insert_address(raw: u128, address: u64, mask: u128) -> u128 {
    (raw & !mask) | (address as u128 & mask)
}
