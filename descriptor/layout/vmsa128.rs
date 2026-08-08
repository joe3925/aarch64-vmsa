use super::descriptor_layout;

descriptor_layout! {
    bits: 128;
    views {
        pub stage1_leaf as STAGE1_LEAF {
            res1: [D128_VALID];
        }
        pub stage2_leaf as STAGE2_LEAF {
            res1: [D128_VALID];
        }
        pub stage1_table as STAGE1_TABLE {
            res1: [D128_VALID];
        }
        pub stage2_table as STAGE2_TABLE {
            res1: [D128_VALID];
        }
    }
    fields {
        pub D128_VALID: Field<0, 1> in ALL;
        pub D128_ATTR_INDEX: Field<2, 4> in STAGE1_LEAF | STAGE2_LEAF;
        pub D128_NT: Field<6, 1> in ALL;
        pub D128_STAGE1_NDIRTY: Field<7, 1> in STAGE1_LEAF;
        pub D128_STAGE2_DIRTY: Field<7, 1> in STAGE2_LEAF;
        pub D128_SHAREABILITY: Field<8, 2> in STAGE1_LEAF | STAGE2_LEAF;
        pub D128_ACCESS_FLAG: Field<10, 1> in ALL;
        pub D128_LEAF_ALIAS: Field<11, 1> in STAGE1_LEAF | STAGE2_LEAF;
        pub D128_OUTPUT_ADDRESS: Field<12, 44> in ALL;
        pub D128_SOFTWARE: Field<91, 10> in ALL;
        pub D128_SKL: Field<109, 2> in ALL;
        pub D128_CONTIGUOUS: Field<111, 1> in STAGE1_LEAF | STAGE2_LEAF;
        pub D128_DISCH: Field<112, 1> in STAGE1_TABLE;
        pub D128_GUARDED: Field<113, 1> in STAGE1_LEAF;
        pub D128_PROTECTED_OR_ASSURED_ONLY: Field<114, 1>
            in STAGE1_LEAF | STAGE2_LEAF | STAGE1_TABLE;
        pub D128_PI_INDEX: Field<115, 4> in STAGE1_LEAF | STAGE2_LEAF;
        pub D128_PO_INDEX: Field<121, 4> in STAGE1_LEAF | STAGE2_LEAF;
        pub D128_NS_OR_NSTABLE: Field<127, 1>
            in STAGE1_LEAF | STAGE2_LEAF | STAGE1_TABLE;
    }
}

pub const ADDRESS_FIELD_MASK: u128 = D128_OUTPUT_ADDRESS.mask();
