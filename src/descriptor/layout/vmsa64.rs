use super::descriptor_layout;

descriptor_layout! {
    bits: 64;
    views {
        pub stage1_leaf as STAGE1_LEAF {}
        pub stage2_leaf as STAGE2_LEAF {}
        pub stage1_table as STAGE1_TABLE {
            res1: [VMSA64_VALID, VMSA64_TABLE_OR_PAGE];
        }
        pub stage2_table as STAGE2_TABLE {
            res1: [VMSA64_VALID, VMSA64_TABLE_OR_PAGE];
        }
    }
    fields {
        pub VMSA64_VALID: Field<0, 1> in ALL;
        pub VMSA64_TABLE_OR_PAGE: Field<1, 1> in ALL;
        pub VMSA64_STAGE1_ATTR_INDEX: Field<2, 3> in STAGE1_LEAF;
        pub VMSA64_STAGE1_NS: Field<5, 1> in STAGE1_LEAF;
        pub VMSA64_STAGE1_AP: Field<6, 2> in STAGE1_LEAF;
        pub VMSA64_STAGE2_MEM_ATTR: Field<2, 4> in STAGE2_LEAF;
        pub VMSA64_STAGE2_AP: Field<6, 2> in STAGE2_LEAF;
        pub VMSA64_SHAREABILITY: Field<8, 2> in STAGE1_LEAF | STAGE2_LEAF;
        pub VMSA64_ACCESS_FLAG: Field<10, 1> in STAGE1_LEAF | STAGE2_LEAF;
        pub VMSA64_STAGE1_ALIAS: Field<11, 1> in STAGE1_LEAF;
        pub VMSA64_OUTPUT_ADDRESS: Field<12, 36> in ALL;
        pub VMSA64_GUARDED: Field<50, 1> in STAGE1_LEAF;
        pub VMSA64_DIRTY_BIT_MODIFIER: Field<51, 1> in STAGE1_LEAF | STAGE2_LEAF;
        pub VMSA64_CONTIGUOUS: Field<52, 1> in STAGE1_LEAF | STAGE2_LEAF;
        pub VMSA64_PXN: Field<53, 1> in STAGE1_LEAF;
        pub VMSA64_UXN: Field<54, 1> in STAGE1_LEAF;
        pub VMSA64_STAGE2_XN: Field<53, 2> in STAGE2_LEAF;
        pub VMSA64_SOFTWARE: Field<55, 4> in ALL;
        pub VMSA64_PXN_TABLE: Field<59, 1> in STAGE1_TABLE;
        pub VMSA64_UXN_TABLE: Field<60, 1> in STAGE1_TABLE;
        pub VMSA64_AP_TABLE: Field<61, 2> in STAGE1_TABLE;
        pub VMSA64_NS_TABLE: Field<63, 1> in STAGE1_TABLE;
    }
}

pub const ADDRESS_FIELD_MASK: u128 = VMSA64_OUTPUT_ADDRESS.mask();
