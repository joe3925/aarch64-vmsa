use core::ptr;

use crate::features::VmsaFeatures;
use crate::granule::{Level, TranslationGranule};
use crate::layout::DescriptorLayout;
use crate::walkers::TranslationStage;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorKind {
    Block,
    Page,
    Table,
    Invalid,
}

pub trait DescriptorFormat: Copy + Sized + 'static {
    type Raw: Copy + Eq;

    const DESCRIPTOR_BYTES: usize;
    const DESCRIPTOR_SHIFT: u8;
    const FINAL_LEVEL: Level = Level::L3;
    const BASE_LOWEST_ROOT_LEVEL: Level;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level;
    const FEATURES: VmsaFeatures;

    fn invalid() -> Self::Raw;

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw;
    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw);
}
pub trait HasLayout<S, G>: DescriptorFormat
where
    S: TranslationStage,
    G: TranslationGranule,
{
    type Layout: DescriptorLayout<Self, S, G>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Lpa2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128;

impl DescriptorFormat for Vmsa64 {
    type Raw = u64;

    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::L0;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const FEATURES: VmsaFeatures = VmsaFeatures::NONE;

    fn invalid() -> Self::Raw {
        0
    }

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        unsafe { ptr::read_volatile(ptr) }
    }

    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        unsafe { ptr::write_volatile(ptr, raw) }
    }
}

impl DescriptorFormat for Vmsa64Lpa2 {
    type Raw = u64;

    const DESCRIPTOR_BYTES: usize = 8;
    const DESCRIPTOR_SHIFT: u8 = 3;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG1;
    const FEATURES: VmsaFeatures = VmsaFeatures::NONE
        .with_lpa2()
        .with_extended_output_address();

    fn invalid() -> Self::Raw {
        0
    }

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        unsafe { ptr::read_volatile(ptr) }
    }

    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        unsafe { ptr::write_volatile(ptr, raw) }
    }
}

impl DescriptorFormat for Vmsa128 {
    type Raw = u128;

    const DESCRIPTOR_BYTES: usize = 16;
    const DESCRIPTOR_SHIFT: u8 = 4;
    const BASE_LOWEST_ROOT_LEVEL: Level = Level::NEG2;
    const EXTENDED_LOWEST_ROOT_LEVEL: Level = Level::NEG2;
    const FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_d128();

    fn invalid() -> Self::Raw {
        0
    }

    unsafe fn read_descriptor(ptr: *const Self::Raw) -> Self::Raw {
        unsafe { ptr::read_volatile(ptr) }
    }

    unsafe fn write_descriptor(ptr: *mut Self::Raw, raw: Self::Raw) {
        unsafe { ptr::write_volatile(ptr, raw) }
    }
}
