use super::{Field, checked_field_mask, vmsa64};

pub const LPA2_DS_ADDRESS_LOW: Field<12, 38> = Field;
pub const LPA2_DS_ADDRESS_HIGH: Field<8, 2> = Field;
pub const LPA2_64K_ADDRESS_LOW: Field<16, 32> = Field;
pub const LPA2_64K_ADDRESS_HIGH: Field<12, 4> = Field;
pub const LPA2_DS_ACCESS_FLAG: Field<10, 1> = Field;
pub const LPA2_DS_STAGE1_ALIAS: Field<11, 1> = Field;

pub const DS_ADDRESS_FIELD_MASK: u128 = checked_field_mask(
    64,
    &[LPA2_DS_ADDRESS_LOW.mask(), LPA2_DS_ADDRESS_HIGH.mask()],
);
pub const ADDRESS_64K_FIELD_MASK: u128 = checked_field_mask(
    64,
    &[LPA2_64K_ADDRESS_LOW.mask(), LPA2_64K_ADDRESS_HIGH.mask()],
);

pub mod ds_stage1_leaf {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage1_leaf::RES0_MASK & !DS_ADDRESS_FIELD_MASK;
}

pub mod ds_stage2_leaf {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage2_leaf::RES0_MASK & !DS_ADDRESS_FIELD_MASK;
}

pub mod ds_stage1_table {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage1_table::RES0_MASK & !DS_ADDRESS_FIELD_MASK;
}

pub mod ds_stage2_table {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage2_table::RES0_MASK & !DS_ADDRESS_FIELD_MASK;
}

pub mod granule64k_stage1_leaf {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage1_leaf::RES0_MASK & !ADDRESS_64K_FIELD_MASK;
}

pub mod granule64k_stage2_leaf {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage2_leaf::RES0_MASK & !ADDRESS_64K_FIELD_MASK;
}

pub mod granule64k_stage1_table {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage1_table::RES0_MASK & !ADDRESS_64K_FIELD_MASK;
}

pub mod granule64k_stage2_table {
    use super::*;
    pub const RES0_MASK: u128 = vmsa64::stage2_table::RES0_MASK & !ADDRESS_64K_FIELD_MASK;
}
