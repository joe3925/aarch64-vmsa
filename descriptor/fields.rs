use crate::descriptor::RawFieldBlock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Stage1LeafFields {
    pub lower: RawFieldBlock<10>,
    pub upper: RawFieldBlock<3>,
    pub dirty_bit_modifier: bool,
    pub guarded: bool,
    pub software: RawFieldBlock<4>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Stage2LeafFields {
    pub lower: RawFieldBlock<9>,
    pub upper: RawFieldBlock<3>,
    pub dirty_bit_modifier: bool,
    pub software: RawFieldBlock<4>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Stage1TableFields {
    pub upper: RawFieldBlock<5>,
    pub software: RawFieldBlock<4>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Stage2TableFields {
    pub software: RawFieldBlock<4>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Lpa2Stage1LeafFields {
    pub lower: RawFieldBlock<8>,
    pub upper: RawFieldBlock<3>,
    pub dirty_bit_modifier: bool,
    pub guarded: bool,
    pub software: RawFieldBlock<4>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Lpa2Stage2LeafFields {
    pub lower: RawFieldBlock<7>,
    pub upper: RawFieldBlock<3>,
    pub dirty_bit_modifier: bool,
    pub software: RawFieldBlock<4>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage1LeafFields {
    pub low: RawFieldBlock<10>,
    pub high: RawFieldBlock<20>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage2LeafFields {
    pub low: RawFieldBlock<10>,
    pub high: RawFieldBlock<20>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage1TableFields {
    pub low: RawFieldBlock<8>,
    pub high: RawFieldBlock<20>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage2TableFields {
    pub low: RawFieldBlock<8>,
    pub high: RawFieldBlock<20>,
}
