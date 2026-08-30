use super::descriptor_layout;

descriptor_layout! {
    bits: 64;
    views {
        pub stage2_leaf as STAGE2_LEAF {}
        pub stage2_table as STAGE2_TABLE {
            res1: [VALID, TABLE_OR_PAGE];
        }
    }
    fields {
        pub VALID: Field<0, 1> in ALL;
        pub TABLE_OR_PAGE: Field<1, 1> in ALL;
        pub MEM_ATTR: Field<2, 4> in STAGE2_LEAF;
        pub S2AP: Field<6, 2> in STAGE2_LEAF;
        pub SHAREABILITY: Field<8, 2> in STAGE2_LEAF;
        pub ACCESS_FLAG: Field<10, 1> in STAGE2_LEAF | STAGE2_TABLE;
        pub OUTPUT_ADDRESS: Field<12, 36> in ALL;
        pub CONTIGUOUS: Field<52, 1> in STAGE2_LEAF;
        pub XN: Field<54, 1> in STAGE2_LEAF;
        pub SOFTWARE: Field<55, 4> in STAGE2_LEAF | STAGE2_TABLE;
        pub RACFG: Field<60, 2> in STAGE2_LEAF;
        pub WACFG: Field<62, 2> in STAGE2_LEAF;
    }
}

pub const ADDRESS_FIELD_MASK: u128 = OUTPUT_ADDRESS.mask();
