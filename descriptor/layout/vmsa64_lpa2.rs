#![allow(non_camel_case_types)]

use super::{Field, vmsa64};

pub type LPA2_DS_ADDRESS_LOW = Field<12, 38>;
pub type LPA2_DS_ADDRESS_HIGH = Field<8, 2>;
pub type LPA2_64K_ADDRESS_LOW = Field<16, 32>;
pub type LPA2_64K_ADDRESS_HIGH = Field<12, 4>;
pub type LPA2_DS_ACCESS_FLAG = Field<10, 1>;
pub type LPA2_DS_STAGE1_ALIAS = Field<11, 1>;

pub const DS_ADDRESS_FIELD_MASK: u128 = LPA2_DS_ADDRESS_LOW::mask() | LPA2_DS_ADDRESS_HIGH::mask();
pub const ADDRESS_64K_FIELD_MASK: u128 =
    LPA2_64K_ADDRESS_LOW::mask() | LPA2_64K_ADDRESS_HIGH::mask();

pub mod ds_stage1_leaf {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage1_leaf::USED_FIELDS_MASK | DS_ADDRESS_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = vmsa64::VMSA64_VALID::mask();
}

pub mod ds_stage2_leaf {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage2_leaf::USED_FIELDS_MASK | DS_ADDRESS_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = vmsa64::VMSA64_VALID::mask();
}

pub mod ds_stage1_table {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage1_table::USED_FIELDS_MASK | DS_ADDRESS_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = vmsa64::stage1_table::RES1_MASK;
}

pub mod ds_stage2_table {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage2_table::USED_FIELDS_MASK | DS_ADDRESS_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = vmsa64::stage2_table::RES1_MASK;
}

pub mod granule64k_stage1_leaf {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage1_leaf::USED_FIELDS_MASK | ADDRESS_64K_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = vmsa64::VMSA64_VALID::mask();
}

pub mod granule64k_stage2_leaf {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage2_leaf::USED_FIELDS_MASK | ADDRESS_64K_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = vmsa64::VMSA64_VALID::mask();
}

pub mod granule64k_stage1_table {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage1_table::USED_FIELDS_MASK | ADDRESS_64K_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
}

pub mod granule64k_stage2_table {
    use super::*;
    pub const USED_FIELDS_MASK: u128 =
        vmsa64::stage2_table::USED_FIELDS_MASK | ADDRESS_64K_FIELD_MASK;
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
}

pub const USED_FIELDS_MASK: u128 = ds_stage1_leaf::USED_FIELDS_MASK
    | ds_stage2_leaf::USED_FIELDS_MASK
    | ds_stage1_table::USED_FIELDS_MASK
    | ds_stage2_table::USED_FIELDS_MASK
    | granule64k_stage1_leaf::USED_FIELDS_MASK
    | granule64k_stage2_leaf::USED_FIELDS_MASK
    | granule64k_stage1_table::USED_FIELDS_MASK
    | granule64k_stage2_table::USED_FIELDS_MASK;
pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
pub const RES1_MASK: u128 = vmsa64::VMSA64_VALID::mask();

const _: () = {
    assert!(LPA2_DS_ADDRESS_HIGH::mask() == 0x300);
    assert!(LPA2_DS_ACCESS_FLAG::mask() == 1 << 10);
    assert!(LPA2_DS_STAGE1_ALIAS::mask() == 1 << 11);
    assert!(DS_ADDRESS_FIELD_MASK == 0x0003_ffff_ffff_f300);
    assert!(ADDRESS_64K_FIELD_MASK == 0x0000_ffff_ffff_f000);
    assert!(USED_FIELDS_MASK & RES0_MASK == 0);
    assert!(RES0_MASK & RES1_MASK == 0);

    assert_class(
        ds_stage1_leaf::USED_FIELDS_MASK,
        ds_stage1_leaf::RES0_MASK,
        ds_stage1_leaf::RES1_MASK,
    );
    assert_class(
        ds_stage2_leaf::USED_FIELDS_MASK,
        ds_stage2_leaf::RES0_MASK,
        ds_stage2_leaf::RES1_MASK,
    );
    assert_class(
        ds_stage1_table::USED_FIELDS_MASK,
        ds_stage1_table::RES0_MASK,
        ds_stage1_table::RES1_MASK,
    );
    assert_class(
        ds_stage2_table::USED_FIELDS_MASK,
        ds_stage2_table::RES0_MASK,
        ds_stage2_table::RES1_MASK,
    );
    assert_class(
        granule64k_stage1_leaf::USED_FIELDS_MASK,
        granule64k_stage1_leaf::RES0_MASK,
        granule64k_stage1_leaf::RES1_MASK,
    );
    assert_class(
        granule64k_stage2_leaf::USED_FIELDS_MASK,
        granule64k_stage2_leaf::RES0_MASK,
        granule64k_stage2_leaf::RES1_MASK,
    );
};

const fn assert_class(used: u128, res0: u128, res1: u128) {
    assert!(used & res0 == 0);
    assert!(res0 & res1 == 0);
    assert!(used & res1 == res1);
}
