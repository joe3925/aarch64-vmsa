use crate::attrs::{
    FourBit, RawVmsa64PermissionFields, RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs,
    RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, TableAp, ThreeBit,
};
use crate::descriptor::layout::vmsa64 as b;

use super::DescriptorError;

pub(super) fn finish_stage1_leaf(
    mut raw: u128,
    fields: RawVmsa64Stage1LeafAttrs,
    kind_bits: u64,
) -> u128 {
    raw = b::VMSA64_GUARDED.insert(raw, fields.guarded.into());
    raw = insert_permission_fields(raw, fields.permissions);
    raw = b::VMSA64_CONTIGUOUS.insert(raw, fields.contiguous.into());
    raw = b::VMSA64_SOFTWARE.insert(raw, fields.software.bits().into());
    raw | kind_bits as u128
}

pub(super) fn finish_stage2_leaf(
    mut raw: u128,
    fields: RawVmsa64Stage2LeafAttrs,
    kind_bits: u64,
) -> u128 {
    raw = insert_permission_fields(raw, fields.permissions);
    raw = b::VMSA64_CONTIGUOUS.insert(raw, fields.contiguous.into());
    raw = b::VMSA64_SOFTWARE.insert(raw, fields.software.bits().into());
    raw | kind_bits as u128
}

pub(super) fn insert_permission_fields(mut raw: u128, fields: RawVmsa64PermissionFields) -> u128 {
    let primary = fields.primary.bits();
    raw = b::VMSA64_PERMISSION_PRIMARY_LOW.insert(raw, (primary & 1).into());
    raw = b::VMSA64_PERMISSION_PRIMARY_1.insert(raw, ((primary >> 1) & 1).into());
    raw = b::VMSA64_PERMISSION_PRIMARY_2.insert(raw, ((primary >> 2) & 1).into());
    raw = b::VMSA64_PERMISSION_PRIMARY_3.insert(raw, ((primary >> 3) & 1).into());
    raw = b::VMSA64_PERMISSION_DIRTY.insert(raw, fields.dirty.into());
    b::VMSA64_PERMISSION_OVERLAY.insert(raw, fields.overlay.bits().into())
}

pub(super) fn extract_permission_fields(raw: u128) -> RawVmsa64PermissionFields {
    let primary = b::VMSA64_PERMISSION_PRIMARY_LOW.extract(raw)
        | b::VMSA64_PERMISSION_PRIMARY_1.extract(raw) << 1
        | b::VMSA64_PERMISSION_PRIMARY_2.extract(raw) << 2
        | b::VMSA64_PERMISSION_PRIMARY_3.extract(raw) << 3;
    RawVmsa64PermissionFields {
        primary: FourBit::from_masked(primary),
        dirty: b::VMSA64_PERMISSION_DIRTY.extract(raw) != 0,
        overlay: ThreeBit::from_masked(b::VMSA64_PERMISSION_OVERLAY.extract(raw)),
    }
}

pub(super) fn finish_table(mut raw: u128, software: FourBit) -> u128 {
    raw = b::VMSA64_SOFTWARE.insert(raw, software.bits().into());
    raw = b::VMSA64_VALID.insert(raw, 1);
    b::VMSA64_TABLE_OR_PAGE.insert(raw, 1)
}

pub(super) fn decode_stage1_table(raw: u64) -> RawVmsa64Stage1TableAttrs {
    let raw = raw as u128;
    RawVmsa64Stage1TableAttrs {
        access_flag: b::VMSA64_ACCESS_FLAG.extract(raw) != 0,
        privileged_execute_never_limit: b::VMSA64_PXN_TABLE.extract(raw) != 0,
        unprivileged_execute_never_limit: b::VMSA64_UXN_TABLE.extract(raw) != 0,
        ap_table: TableAp::from_masked(b::VMSA64_AP_TABLE.extract(raw)),
        ns_table: b::VMSA64_NS_TABLE.extract(raw) != 0,
        software: FourBit::from_masked(b::VMSA64_SOFTWARE.extract(raw)),
    }
}

pub(super) fn decode_stage2_table(raw: u64) -> RawVmsa64Stage2TableAttrs {
    RawVmsa64Stage2TableAttrs {
        access_flag: b::VMSA64_ACCESS_FLAG.extract(raw as u128) != 0,
        software: FourBit::from_masked(b::VMSA64_SOFTWARE.extract(raw as u128)),
    }
}

pub(super) fn check_reserved(raw: u128, res0: u128, res1: u128) -> Result<(), DescriptorError> {
    if raw & res0 != 0 || raw & res1 != res1 {
        Err(DescriptorError::InvalidReservedBitState)
    } else {
        Ok(())
    }
}
