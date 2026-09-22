mod smmu_v2;
mod vmsa128;
mod vmsa64;
mod vmsa64_family;
mod vmsa64_lpa2;

pub(crate) use smmu_v2::SmmuV2Vmsa64Stage2Layout;

#[cfg(target_has_atomic = "64")]
use portable_atomic::AtomicU64;
#[cfg(all(target_has_atomic = "64", not(target_has_atomic = "128")))]
use portable_atomic::Ordering;
#[cfg(target_has_atomic = "128")]
use portable_atomic::{AtomicU128, Ordering};

use crate::address::{Level, TranslationGranule};
use crate::arch::{Capability, FeatureRequirements};
use crate::config::format::{DescriptorEndian, Vmsa64, Vmsa64Lpa2, Vmsa128};
use crate::table::{TableGeometry, TableTransition};
use crate::translation::TranslationStage;

pub use paging::descriptor::{
    DescriptorError, DescriptorFormat, DescriptorKind, DescriptorLayout, NextTableDescriptor,
    SupportsLiveDescriptorIo,
};

pub trait ArmDescriptorFormat: DescriptorFormat {
    const REQUIRED_FEATURES: FeatureRequirements;
}

pub trait ArmDescriptorLayout<G>: DescriptorLayout<G>
where
    G: TranslationGranule,
    Self::Format: ArmDescriptorFormat,
{
    const REQUIRED_FEATURES: FeatureRequirements =
        <Self::Format as ArmDescriptorFormat>::REQUIRED_FEATURES;
}

impl<E: DescriptorEndian> ArmDescriptorFormat for Vmsa64<E> {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}

impl<E: DescriptorEndian> ArmDescriptorFormat for Vmsa64Lpa2<E> {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .require(Capability::Lpa2)
        .require(Capability::ExtendedOutputAddress);
}

impl<E: DescriptorEndian> ArmDescriptorFormat for Vmsa128<E> {
    const REQUIRED_FEATURES: FeatureRequirements =
        FeatureRequirements::NONE.require(Capability::D128);
}

mod private {
    pub trait InterpretationSealed {}
}

pub trait HasLayout<S, G>: ArmDescriptorFormat
where
    S: TranslationStage,
    G: TranslationGranule,
{
    type Layout: ArmDescriptorLayout<G, Format = Self>;
}

/// Selects the raw descriptor interpretation used by a translation regime.
pub trait DescriptorInterpretation: private::InterpretationSealed + Copy + 'static {
    /// Whether stage-1 permission indirection is defined for this interpreter.
    const SUPPORTS_STAGE1_PERMISSION_INDIRECTION: bool;
    /// Whether stage-1 permission overlays are defined for this interpreter.
    const SUPPORTS_STAGE1_PERMISSION_OVERLAYS: bool;
    const USES_SMMUV3_STAGE1_PERMISSION_REGISTERS: bool = false;
    const USES_SMMUV3_STAGE1_MEMORY_ATTRIBUTES: bool = false;
}

/// Maps a format, stage, and granule to the layout understood by an interpreter.
pub trait InterpretsDescriptors<F, S, G>: DescriptorInterpretation
where
    F: ArmDescriptorFormat,
    S: TranslationStage,
    G: TranslationGranule,
{
    type Layout: ArmDescriptorLayout<G, Format = F>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeDescriptors;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmmuV2Descriptors;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmmuV3Descriptors;

impl private::InterpretationSealed for PeDescriptors {}
impl private::InterpretationSealed for SmmuV2Descriptors {}
impl private::InterpretationSealed for SmmuV3Descriptors {}
impl DescriptorInterpretation for PeDescriptors {
    const SUPPORTS_STAGE1_PERMISSION_INDIRECTION: bool = true;
    const SUPPORTS_STAGE1_PERMISSION_OVERLAYS: bool = true;
}
impl DescriptorInterpretation for SmmuV2Descriptors {
    const SUPPORTS_STAGE1_PERMISSION_INDIRECTION: bool = false;
    const SUPPORTS_STAGE1_PERMISSION_OVERLAYS: bool = false;
}
impl DescriptorInterpretation for SmmuV3Descriptors {
    const SUPPORTS_STAGE1_PERMISSION_INDIRECTION: bool = true;
    const SUPPORTS_STAGE1_PERMISSION_OVERLAYS: bool = false;
    const USES_SMMUV3_STAGE1_PERMISSION_REGISTERS: bool = true;
    const USES_SMMUV3_STAGE1_MEMORY_ATTRIBUTES: bool = true;
}

impl<F, S, G> InterpretsDescriptors<F, S, G> for PeDescriptors
where
    F: ArmDescriptorFormat + HasLayout<S, G>,
    S: TranslationStage,
    G: TranslationGranule,
{
    type Layout = F::Layout;
}

impl<F, S, G> InterpretsDescriptors<F, S, G> for SmmuV3Descriptors
where
    F: ArmDescriptorFormat + HasLayout<S, G>,
    S: TranslationStage,
    G: TranslationGranule,
{
    type Layout = F::Layout;
}

impl<E, G> InterpretsDescriptors<Vmsa64<E>, crate::translation::Stage1, G> for SmmuV2Descriptors
where
    E: DescriptorEndian,
    G: TranslationGranule,
{
    type Layout = <Vmsa64<E> as HasLayout<crate::translation::Stage1, G>>::Layout;
}

impl<E, G> InterpretsDescriptors<Vmsa64<E>, crate::translation::Stage2, G> for SmmuV2Descriptors
where
    E: DescriptorEndian,
    G: TranslationGranule,
{
    type Layout = smmu_v2::SmmuV2Vmsa64Stage2Layout<E, G>;
}

#[cfg(target_has_atomic = "64")]
unsafe impl<E: DescriptorEndian> SupportsLiveDescriptorIo for Vmsa64<E> {}
#[cfg(target_has_atomic = "64")]
unsafe impl<E: DescriptorEndian> SupportsLiveDescriptorIo for Vmsa64Lpa2<E> {}
#[cfg(target_has_atomic = "128")]
unsafe impl<E: DescriptorEndian> SupportsLiveDescriptorIo for Vmsa128<E> {}

unsafe impl<E: DescriptorEndian> DescriptorFormat for Vmsa64<E> {
    type Raw = u64;
    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const MAX_INPUT_ADDRESS_BITS: u8 = 52;
    const OUTPUT_ADDRESS_BITS: u8 = 48;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const FINAL_LEVEL: Level = Level::L3;
    const SUPPORTED_OUTPUT_ADDRESS_BITS: &'static [u8] = &[32, 36, 40, 42, 44, 48, 52];

    fn invalid() -> Self::Raw {
        0
    }
    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller gives an aligned and readable descriptor pointer.
            E::decode_u64(unsafe { AtomicU64::from_ptr(ptr.cast_mut()).load(Ordering::Acquire) })
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller gives an aligned and readable descriptor pointer.
            E::decode_u64(unsafe { core::ptr::read_volatile(ptr) })
        }
    }
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller gives an aligned and writable descriptor pointer.
            unsafe { AtomicU64::from_ptr(ptr).store(E::encode_u64(raw), Ordering::Release) }
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller gives an aligned and writable descriptor pointer.
            unsafe { core::ptr::write_volatile(ptr, E::encode_u64(raw)) }
        }
    }
}

unsafe impl<E: DescriptorEndian> DescriptorFormat for Vmsa64Lpa2<E> {
    type Raw = u64;
    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const MAX_INPUT_ADDRESS_BITS: u8 = 52;
    const OUTPUT_ADDRESS_BITS: u8 = 52;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const FINAL_LEVEL: Level = Level::L3;
    const SUPPORTED_OUTPUT_ADDRESS_BITS: &'static [u8] = &[32, 36, 40, 42, 44, 48, 52];

    fn invalid() -> Self::Raw {
        0
    }
    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller gives an aligned and readable descriptor pointer.
            E::decode_u64(unsafe { AtomicU64::from_ptr(ptr.cast_mut()).load(Ordering::Acquire) })
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller gives an aligned and readable descriptor pointer.
            E::decode_u64(unsafe { core::ptr::read_volatile(ptr) })
        }
    }
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        #[cfg(target_has_atomic = "64")]
        {
            // SAFETY: The caller gives an aligned and writable descriptor pointer.
            unsafe { AtomicU64::from_ptr(ptr).store(E::encode_u64(raw), Ordering::Release) }
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            // SAFETY: The caller gives an aligned and writable descriptor pointer.
            unsafe { core::ptr::write_volatile(ptr, E::encode_u64(raw)) }
        }
    }
}

unsafe impl<E: DescriptorEndian> DescriptorFormat for Vmsa128<E> {
    type Raw = u128;
    const DESCRIPTOR_BYTES: usize = 16;
    const DESCRIPTOR_SHIFT: u8 = 4;
    const MAX_INPUT_ADDRESS_BITS: u8 = 56;
    const OUTPUT_ADDRESS_BITS: u8 = 56;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG2;
    const FINAL_LEVEL: Level = Level::L3;
    const SUPPORTED_OUTPUT_ADDRESS_BITS: &'static [u8] = &[32, 36, 40, 42, 44, 48, 52, 56];

    fn invalid() -> Self::Raw {
        0
    }
    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        #[cfg(target_has_atomic = "128")]
        {
            // SAFETY: The caller gives an aligned and readable descriptor pointer.
            E::decode_u128(unsafe { AtomicU128::from_ptr(ptr.cast_mut()).load(Ordering::Acquire) })
        }
        #[cfg(not(target_has_atomic = "128"))]
        {
            // SAFETY: The caller gives an aligned and readable descriptor pointer.
            E::decode_u128(unsafe { core::ptr::read_volatile(ptr) })
        }
    }
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        #[cfg(target_has_atomic = "128")]
        {
            // SAFETY: The caller gives an aligned and writable descriptor pointer.
            unsafe { AtomicU128::from_ptr(ptr).store(E::encode_u128(raw), Ordering::Release) }
        }
        #[cfg(not(target_has_atomic = "128"))]
        {
            // SAFETY: The caller gives an aligned and writable descriptor pointer.
            unsafe { core::ptr::write_volatile(ptr, E::encode_u128(raw)) }
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

/// Clears the offset bits that a leaf at `level` does not use.
///
/// The low bits of a block descriptor output address are RES0; hardware treats them as
/// zero, so decoding must do the same. Without this, `resolve_output` computes
/// `base + offset` from a base that still carries those bits and returns a PA the
/// hardware would never produce.
pub(crate) fn align_output<F, G>(address: u64, level: Level) -> u64
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    match TableGeometry::<F, G>::checked_level_shift(level) {
        Some(shift) if shift < u64::BITS as u8 => address & !((1u64 << shift) - 1),
        _ => address,
    }
}

pub(crate) const fn insert_address(raw: u128, address: u64, mask: u128) -> u128 {
    (raw & !mask) | (address as u128 & mask)
}
