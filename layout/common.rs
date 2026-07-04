use crate::addr::PhysAddr;

pub fn encode_direct_address(address: PhysAddr, address_field_mask: u128) -> u128 {
    address.0 as u128 & address_field_mask
}

pub fn decode_direct_output_address(raw: u128, address_field_mask: u128) -> PhysAddr {
    PhysAddr((raw & address_field_mask) as u64)
}

pub const fn lower_bits_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}
