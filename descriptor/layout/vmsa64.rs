#![allow(non_camel_case_types)]

use super::Field;

pub type VMSA64_VALID = Field<0, 1>;
pub type VMSA64_TABLE_OR_PAGE = Field<1, 1>;
pub type VMSA64_STAGE1_ATTR_INDEX = Field<2, 3>;
pub type VMSA64_STAGE1_NS = Field<5, 1>;
pub type VMSA64_STAGE1_AP = Field<6, 2>;
pub type VMSA64_STAGE2_MEM_ATTR = Field<2, 4>;
pub type VMSA64_STAGE2_AP = Field<6, 2>;
pub type VMSA64_SHAREABILITY = Field<8, 2>;
pub type VMSA64_ACCESS_FLAG = Field<10, 1>;
pub type VMSA64_STAGE1_ALIAS = Field<11, 1>;
pub type VMSA64_OUTPUT_ADDRESS = Field<12, 36>;
pub type VMSA64_GUARDED = Field<50, 1>;
pub type VMSA64_DIRTY_BIT_MODIFIER = Field<51, 1>;
pub type VMSA64_CONTIGUOUS = Field<52, 1>;
pub type VMSA64_PXN = Field<53, 1>;
pub type VMSA64_UXN = Field<54, 1>;
pub type VMSA64_STAGE2_XN = Field<53, 2>;
pub type VMSA64_SOFTWARE = Field<55, 4>;
pub type VMSA64_PXN_TABLE = Field<59, 1>;
pub type VMSA64_UXN_TABLE = Field<60, 1>;
pub type VMSA64_AP_TABLE = Field<61, 2>;
pub type VMSA64_NS_TABLE = Field<63, 1>;

pub const ADDRESS_FIELD_MASK: u128 = VMSA64_OUTPUT_ADDRESS::mask();

pub mod stage1_leaf {
    use super::*;
    pub const USED_FIELDS_MASK: u128 = VMSA64_VALID::mask()
        | VMSA64_TABLE_OR_PAGE::mask()
        | VMSA64_STAGE1_ATTR_INDEX::mask()
        | VMSA64_STAGE1_NS::mask()
        | VMSA64_STAGE1_AP::mask()
        | VMSA64_SHAREABILITY::mask()
        | VMSA64_ACCESS_FLAG::mask()
        | VMSA64_STAGE1_ALIAS::mask()
        | VMSA64_OUTPUT_ADDRESS::mask()
        | VMSA64_GUARDED::mask()
        | VMSA64_DIRTY_BIT_MODIFIER::mask()
        | VMSA64_CONTIGUOUS::mask()
        | VMSA64_PXN::mask()
        | VMSA64_UXN::mask()
        | VMSA64_SOFTWARE::mask();
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = VMSA64_VALID::mask();
}

pub mod stage2_leaf {
    use super::*;
    pub const USED_FIELDS_MASK: u128 = VMSA64_VALID::mask()
        | VMSA64_TABLE_OR_PAGE::mask()
        | VMSA64_STAGE2_MEM_ATTR::mask()
        | VMSA64_STAGE2_AP::mask()
        | VMSA64_SHAREABILITY::mask()
        | VMSA64_ACCESS_FLAG::mask()
        | VMSA64_OUTPUT_ADDRESS::mask()
        | VMSA64_DIRTY_BIT_MODIFIER::mask()
        | VMSA64_CONTIGUOUS::mask()
        | VMSA64_STAGE2_XN::mask()
        | VMSA64_SOFTWARE::mask();
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = VMSA64_VALID::mask();
}

pub mod stage1_table {
    use super::*;
    pub const USED_FIELDS_MASK: u128 = VMSA64_VALID::mask()
        | VMSA64_TABLE_OR_PAGE::mask()
        | VMSA64_OUTPUT_ADDRESS::mask()
        | VMSA64_SOFTWARE::mask()
        | VMSA64_PXN_TABLE::mask()
        | VMSA64_UXN_TABLE::mask()
        | VMSA64_AP_TABLE::mask()
        | VMSA64_NS_TABLE::mask();
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = VMSA64_VALID::mask() | VMSA64_TABLE_OR_PAGE::mask();
}

pub mod stage2_table {
    use super::*;
    pub const USED_FIELDS_MASK: u128 = VMSA64_VALID::mask()
        | VMSA64_TABLE_OR_PAGE::mask()
        | VMSA64_OUTPUT_ADDRESS::mask()
        | VMSA64_SOFTWARE::mask();
    pub const RES0_MASK: u128 = (!USED_FIELDS_MASK) & u64::MAX as u128;
    pub const RES1_MASK: u128 = VMSA64_VALID::mask() | VMSA64_TABLE_OR_PAGE::mask();
}

const _: () = {
    assert_class(
        stage1_leaf::USED_FIELDS_MASK,
        stage1_leaf::RES0_MASK,
        stage1_leaf::RES1_MASK,
    );
    assert_class(
        stage2_leaf::USED_FIELDS_MASK,
        stage2_leaf::RES0_MASK,
        stage2_leaf::RES1_MASK,
    );
    assert_class(
        stage1_table::USED_FIELDS_MASK,
        stage1_table::RES0_MASK,
        stage1_table::RES1_MASK,
    );
    assert_class(
        stage2_table::USED_FIELDS_MASK,
        stage2_table::RES0_MASK,
        stage2_table::RES1_MASK,
    );

    assert_disjoint(&[
        VMSA64_VALID::mask(),
        VMSA64_TABLE_OR_PAGE::mask(),
        VMSA64_STAGE1_ATTR_INDEX::mask(),
        VMSA64_STAGE1_NS::mask(),
        VMSA64_STAGE1_AP::mask(),
        VMSA64_SHAREABILITY::mask(),
        VMSA64_ACCESS_FLAG::mask(),
        VMSA64_STAGE1_ALIAS::mask(),
        VMSA64_OUTPUT_ADDRESS::mask(),
        VMSA64_GUARDED::mask(),
        VMSA64_DIRTY_BIT_MODIFIER::mask(),
        VMSA64_CONTIGUOUS::mask(),
        VMSA64_PXN::mask(),
        VMSA64_UXN::mask(),
        VMSA64_SOFTWARE::mask(),
    ]);
    assert_disjoint(&[
        VMSA64_VALID::mask(),
        VMSA64_TABLE_OR_PAGE::mask(),
        VMSA64_STAGE2_MEM_ATTR::mask(),
        VMSA64_STAGE2_AP::mask(),
        VMSA64_SHAREABILITY::mask(),
        VMSA64_ACCESS_FLAG::mask(),
        VMSA64_OUTPUT_ADDRESS::mask(),
        VMSA64_DIRTY_BIT_MODIFIER::mask(),
        VMSA64_CONTIGUOUS::mask(),
        VMSA64_STAGE2_XN::mask(),
        VMSA64_SOFTWARE::mask(),
    ]);
    assert_disjoint(&[
        VMSA64_VALID::mask(),
        VMSA64_TABLE_OR_PAGE::mask(),
        VMSA64_OUTPUT_ADDRESS::mask(),
        VMSA64_SOFTWARE::mask(),
        VMSA64_PXN_TABLE::mask(),
        VMSA64_UXN_TABLE::mask(),
        VMSA64_AP_TABLE::mask(),
        VMSA64_NS_TABLE::mask(),
    ]);
};

const fn assert_class(used: u128, res0: u128, res1: u128) {
    assert!(used & res0 == 0);
    assert!(res0 & res1 == 0);
    assert!(used & res1 == res1);
}

const fn assert_disjoint(fields: &[u128]) {
    let mut used = 0;
    let mut index = 0;
    while index < fields.len() {
        assert!(used & fields[index] == 0);
        used |= fields[index];
        index += 1;
    }
}
