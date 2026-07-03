use crate::format::DescriptorFormat;
pub enum DescriptorKind {
    Block,
    Page,
    Table,
    Invalid,
}
#[repr(transparent)]
#[derive(Debug, Eq, PartialEq)]
pub struct EncodedTableAttrs<F: DescriptorFormat> {
    raw: F::Raw,
}

impl<F: DescriptorFormat> Copy for EncodedTableAttrs<F> {}

impl<F: DescriptorFormat> Clone for EncodedTableAttrs<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: DescriptorFormat> EncodedTableAttrs<F> {
    pub const unsafe fn from_raw_unchecked(raw: F::Raw) -> Self {
        Self { raw }
    }

    pub const fn bits(self) -> F::Raw {
        self.raw
    }
}
