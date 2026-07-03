use crate::format::DescriptorFormat;

#[repr(transparent)]
#[derive(Eq, PartialEq)]
pub struct EncodedLeafAttrs<F: DescriptorFormat> {
    raw: F::Raw,
}

impl<F: DescriptorFormat> Copy for EncodedLeafAttrs<F> {}

impl<F: DescriptorFormat> Clone for EncodedLeafAttrs<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: DescriptorFormat> EncodedLeafAttrs<F> {
    pub const unsafe fn from_raw_unchecked(raw: F::Raw) -> Self {
        Self { raw }
    }

    pub const fn bits(self) -> F::Raw {
        self.raw
    }
}
