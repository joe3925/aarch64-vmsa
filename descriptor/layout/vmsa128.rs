#![allow(non_camel_case_types)]

use super::Field;

pub type D128_VALID = Field<0, 1>;
pub type D128_ATTR_INDEX = Field<2, 4>;
pub type D128_NT = Field<6, 1>;
pub type D128_STAGE1_NDIRTY = Field<7, 1>;
pub type D128_STAGE2_DIRTY = Field<7, 1>;
pub type D128_SHAREABILITY = Field<8, 2>;
pub type D128_ACCESS_FLAG = Field<10, 1>;
pub type D128_LEAF_ALIAS = Field<11, 1>;
pub type D128_OUTPUT_ADDRESS = Field<12, 44>;
pub type D128_SOFTWARE = Field<91, 10>;
pub type D128_SKL = Field<109, 2>;
pub type D128_CONTIGUOUS = Field<111, 1>;
pub type D128_DISCH = Field<112, 1>;
pub type D128_GUARDED = Field<113, 1>;
pub type D128_PROTECTED_OR_ASSURED_ONLY = Field<114, 1>;
pub type D128_PI_INDEX = Field<115, 4>;
pub type D128_PO_INDEX = Field<121, 4>;
pub type D128_NS_OR_NSTABLE = Field<127, 1>;

pub const ADDRESS_FIELD_MASK: u128 = D128_OUTPUT_ADDRESS::mask();

pub mod stage1_leaf {
    use super::*;

    pub const USED_FIELDS_MASK: u128 = D128_VALID::mask()
        | D128_ATTR_INDEX::mask()
        | D128_NT::mask()
        | D128_STAGE1_NDIRTY::mask()
        | D128_SHAREABILITY::mask()
        | D128_ACCESS_FLAG::mask()
        | D128_LEAF_ALIAS::mask()
        | D128_OUTPUT_ADDRESS::mask()
        | D128_SOFTWARE::mask()
        | D128_SKL::mask()
        | D128_CONTIGUOUS::mask()
        | D128_GUARDED::mask()
        | D128_PROTECTED_OR_ASSURED_ONLY::mask()
        | D128_PI_INDEX::mask()
        | D128_PO_INDEX::mask()
        | D128_NS_OR_NSTABLE::mask();
    pub const RES0_MASK: u128 = !USED_FIELDS_MASK;
    pub const RES1_MASK: u128 = D128_VALID::mask();
}

pub mod stage2_leaf {
    use super::*;

    pub const USED_FIELDS_MASK: u128 = D128_VALID::mask()
        | D128_ATTR_INDEX::mask()
        | D128_NT::mask()
        | D128_STAGE2_DIRTY::mask()
        | D128_SHAREABILITY::mask()
        | D128_ACCESS_FLAG::mask()
        | D128_LEAF_ALIAS::mask()
        | D128_OUTPUT_ADDRESS::mask()
        | D128_SOFTWARE::mask()
        | D128_SKL::mask()
        | D128_CONTIGUOUS::mask()
        | D128_PROTECTED_OR_ASSURED_ONLY::mask()
        | D128_PI_INDEX::mask()
        | D128_PO_INDEX::mask()
        | D128_NS_OR_NSTABLE::mask();
    pub const RES0_MASK: u128 = !USED_FIELDS_MASK;
    pub const RES1_MASK: u128 = D128_VALID::mask();
}

pub mod stage1_table {
    use super::*;

    pub const USED_FIELDS_MASK: u128 = D128_VALID::mask()
        | D128_NT::mask()
        | D128_ACCESS_FLAG::mask()
        | D128_OUTPUT_ADDRESS::mask()
        | D128_SOFTWARE::mask()
        | D128_SKL::mask()
        | D128_DISCH::mask()
        | D128_PROTECTED_OR_ASSURED_ONLY::mask()
        | D128_NS_OR_NSTABLE::mask();
    pub const RES0_MASK: u128 = !USED_FIELDS_MASK;
    pub const RES1_MASK: u128 = D128_VALID::mask();
}

pub mod stage2_table {
    use super::*;

    pub const USED_FIELDS_MASK: u128 = D128_VALID::mask()
        | D128_NT::mask()
        | D128_ACCESS_FLAG::mask()
        | D128_OUTPUT_ADDRESS::mask()
        | D128_SOFTWARE::mask()
        | D128_SKL::mask();
    pub const RES0_MASK: u128 = !USED_FIELDS_MASK;
    pub const RES1_MASK: u128 = D128_VALID::mask();
}

const _: () = {
    assert!(D128_PI_INDEX::mask() == (0xfu128 << 115));
    assert!(D128_PO_INDEX::mask() == (0xfu128 << 121));
    assert!(D128_DISCH::mask() == (1u128 << 112));
    assert!(D128_STAGE1_NDIRTY::mask() == (1u128 << 7));
    assert!(D128_STAGE2_DIRTY::mask() == (1u128 << 7));
    assert!(D128_SOFTWARE::mask() == (0x3ffu128 << 91));

    assert_masks(
        stage1_leaf::USED_FIELDS_MASK,
        stage1_leaf::RES0_MASK,
        stage1_leaf::RES1_MASK,
    );
    assert_masks(
        stage2_leaf::USED_FIELDS_MASK,
        stage2_leaf::RES0_MASK,
        stage2_leaf::RES1_MASK,
    );
    assert_masks(
        stage1_table::USED_FIELDS_MASK,
        stage1_table::RES0_MASK,
        stage1_table::RES1_MASK,
    );
    assert_masks(
        stage2_table::USED_FIELDS_MASK,
        stage2_table::RES0_MASK,
        stage2_table::RES1_MASK,
    );

    assert_pairwise_disjoint(&[
        D128_VALID::mask(),
        D128_ATTR_INDEX::mask(),
        D128_NT::mask(),
        D128_STAGE1_NDIRTY::mask(),
        D128_SHAREABILITY::mask(),
        D128_ACCESS_FLAG::mask(),
        D128_LEAF_ALIAS::mask(),
        D128_OUTPUT_ADDRESS::mask(),
        D128_SOFTWARE::mask(),
        D128_SKL::mask(),
        D128_CONTIGUOUS::mask(),
        D128_GUARDED::mask(),
        D128_PROTECTED_OR_ASSURED_ONLY::mask(),
        D128_PI_INDEX::mask(),
        D128_PO_INDEX::mask(),
        D128_NS_OR_NSTABLE::mask(),
    ]);
    assert_pairwise_disjoint(&[
        D128_VALID::mask(),
        D128_ATTR_INDEX::mask(),
        D128_NT::mask(),
        D128_STAGE2_DIRTY::mask(),
        D128_SHAREABILITY::mask(),
        D128_ACCESS_FLAG::mask(),
        D128_LEAF_ALIAS::mask(),
        D128_OUTPUT_ADDRESS::mask(),
        D128_SOFTWARE::mask(),
        D128_SKL::mask(),
        D128_CONTIGUOUS::mask(),
        D128_PROTECTED_OR_ASSURED_ONLY::mask(),
        D128_PI_INDEX::mask(),
        D128_PO_INDEX::mask(),
        D128_NS_OR_NSTABLE::mask(),
    ]);
    assert_pairwise_disjoint(&[
        D128_VALID::mask(),
        D128_NT::mask(),
        D128_ACCESS_FLAG::mask(),
        D128_OUTPUT_ADDRESS::mask(),
        D128_SOFTWARE::mask(),
        D128_SKL::mask(),
        D128_DISCH::mask(),
        D128_PROTECTED_OR_ASSURED_ONLY::mask(),
        D128_NS_OR_NSTABLE::mask(),
    ]);
    assert_pairwise_disjoint(&[
        D128_VALID::mask(),
        D128_NT::mask(),
        D128_ACCESS_FLAG::mask(),
        D128_OUTPUT_ADDRESS::mask(),
        D128_SOFTWARE::mask(),
        D128_SKL::mask(),
    ]);
};

const fn assert_masks(used: u128, res0: u128, res1: u128) {
    assert!(used & res0 == 0, "used fields overlap RES0");
    assert!(res0 & res1 == 0, "RES0 overlaps RES1");
    assert!(used & res1 == res1, "RES1 field is not owned by the packer");
}

const fn assert_pairwise_disjoint(fields: &[u128]) {
    let mut used = 0;
    let mut index = 0;
    while index < fields.len() {
        assert!(used & fields[index] == 0, "architectural fields overlap");
        used |= fields[index];
        index += 1;
    }
}
