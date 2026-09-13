use core::marker::PhantomData;

mod private {
    pub trait Sealed {}
}

/// Byte order used to store translation-table descriptors in memory.
pub trait DescriptorEndian: private::Sealed + Copy + 'static {
    fn decode_u64(storage: u64) -> u64;
    fn encode_u64(raw: u64) -> u64;
    fn decode_u128(storage: u128) -> u128;
    fn encode_u128(raw: u128) -> u128;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeEndian;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LittleEndian;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BigEndian;

impl private::Sealed for NativeEndian {}
impl private::Sealed for LittleEndian {}
impl private::Sealed for BigEndian {}

impl DescriptorEndian for NativeEndian {
    fn decode_u64(storage: u64) -> u64 {
        storage
    }
    fn encode_u64(raw: u64) -> u64 {
        raw
    }
    fn decode_u128(storage: u128) -> u128 {
        storage
    }
    fn encode_u128(raw: u128) -> u128 {
        raw
    }
}

impl DescriptorEndian for LittleEndian {
    fn decode_u64(storage: u64) -> u64 {
        u64::from_le(storage)
    }
    fn encode_u64(raw: u64) -> u64 {
        raw.to_le()
    }
    fn decode_u128(storage: u128) -> u128 {
        u128::from_le(storage)
    }
    fn encode_u128(raw: u128) -> u128 {
        raw.to_le()
    }
}

impl DescriptorEndian for BigEndian {
    fn decode_u64(storage: u64) -> u64 {
        u64::from_be(storage)
    }
    fn encode_u64(raw: u64) -> u64 {
        raw.to_be()
    }
    fn decode_u128(storage: u128) -> u128 {
        u128::from_be(storage)
    }
    fn encode_u128(raw: u128) -> u128 {
        raw.to_be()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64<E = NativeEndian>(PhantomData<fn() -> E>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Lpa2<E = NativeEndian>(PhantomData<fn() -> E>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128<E = NativeEndian>(PhantomData<fn() -> E>);
