use crate::attrs::{
    FourBit, RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs,
    RawVmsa64Stage2TableAttrs, TableAp,
};
use crate::descriptor::layout::vmsa64 as b;

use super::DescriptorError;

pub(super) fn finish_stage1_leaf(
    mut raw: u128,
    fields: RawVmsa64Stage1LeafAttrs,
    kind_bits: u64,
) -> u128 {
    raw = b::VMSA64_GUARDED::insert(raw, fields.guarded.into());
    raw = b::VMSA64_DIRTY_BIT_MODIFIER::insert(raw, fields.dirty_bit_modifier.into());
    raw = b::VMSA64_CONTIGUOUS::insert(raw, fields.contiguous.into());
    raw = b::VMSA64_PXN::insert(raw, fields.privileged_execute_never.into());
    raw = b::VMSA64_UXN::insert(raw, fields.unprivileged_execute_never.into());
    raw = b::VMSA64_SOFTWARE::insert(raw, fields.software.bits().into());
    raw | kind_bits as u128
}

pub(super) fn finish_stage2_leaf(
    mut raw: u128,
    fields: RawVmsa64Stage2LeafAttrs,
    kind_bits: u64,
) -> u128 {
    raw = b::VMSA64_DIRTY_BIT_MODIFIER::insert(raw, fields.dirty_bit_modifier.into());
    raw = b::VMSA64_CONTIGUOUS::insert(raw, fields.contiguous.into());
    raw = b::VMSA64_STAGE2_XN::insert(raw, fields.execute_never.bits().into());
    raw = b::VMSA64_SOFTWARE::insert(raw, fields.software.bits().into());
    raw | kind_bits as u128
}

pub(super) fn finish_table(mut raw: u128, software: FourBit) -> u128 {
    raw = b::VMSA64_SOFTWARE::insert(raw, software.bits().into());
    raw = b::VMSA64_VALID::insert(raw, 1);
    b::VMSA64_TABLE_OR_PAGE::insert(raw, 1)
}

pub(super) fn decode_stage1_table(raw: u64) -> RawVmsa64Stage1TableAttrs {
    let raw = raw as u128;
    RawVmsa64Stage1TableAttrs {
        privileged_execute_never_limit: b::VMSA64_PXN_TABLE::extract(raw) != 0,
        unprivileged_execute_never_limit: b::VMSA64_UXN_TABLE::extract(raw) != 0,
        ap_table: TableAp::from_masked(b::VMSA64_AP_TABLE::extract(raw)),
        ns_table: b::VMSA64_NS_TABLE::extract(raw) != 0,
        software: FourBit::from_masked(b::VMSA64_SOFTWARE::extract(raw)),
    }
}

pub(super) fn decode_stage2_table(raw: u64) -> RawVmsa64Stage2TableAttrs {
    RawVmsa64Stage2TableAttrs {
        software: FourBit::from_masked(b::VMSA64_SOFTWARE::extract(raw as u128)),
    }
}

pub(super) fn check_reserved(raw: u128, res0: u128, res1: u128) -> Result<(), DescriptorError> {
    if raw & res0 != 0 || raw & res1 != res1 {
        Err(DescriptorError::InvalidReservedBitState)
    } else {
        Ok(())
    }
}
