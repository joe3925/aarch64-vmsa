use core::marker::PhantomData;

use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;

use super::{AccessError, TableGeometry, TablePhysAddr, TranslationTable, TranslationTableMut};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableWalkPath<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    bits: u128,
    len: u8,
    _marker: PhantomData<(F, G)>,
}

impl<F, G> TableWalkPath<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn root() -> Self {
        Self {
            bits: 0,
            len: 0,
            _marker: PhantomData,
        }
    }

    pub const fn len(&self) -> u8 {
        self.len
    }

    pub const fn is_root(&self) -> bool {
        self.len == 0
    }

    pub const fn bits(&self) -> u128 {
        self.bits
    }

    pub fn push(
        &mut self,
        root_level: Level,
        parent_level: Level,
        index: usize,
    ) -> Result<(), AccessError> {
        if root_level.is_after(parent_level) || !parent_level.is_before(F::FINAL_LEVEL) {
            return Err(AccessError::InvalidTableLevel {
                root_level,
                level: parent_level,
                final_level: F::FINAL_LEVEL,
            });
        }

        let expected =
            parent_level
                .distance_from(root_level)
                .ok_or(AccessError::InvalidTableLevel {
                    root_level,
                    level: parent_level,
                    final_level: F::FINAL_LEVEL,
                })?;

        if self.len != expected {
            return Err(AccessError::TablePathLengthMismatch {
                expected,
                actual: self.len,
            });
        }

        let entries = TableGeometry::<F, G>::entries();

        if index >= entries {
            return Err(AccessError::TablePathIndexOutOfRange { index, entries });
        }

        let index_bits = TableGeometry::<F, G>::index_bits();
        let new_len = self.len + 1;

        if new_len as u16 * index_bits as u16 > u128::BITS as u16 {
            return Err(AccessError::TablePathCapacityExceeded {
                len: new_len,
                index_bits,
            });
        }

        let shift = self.len as u32 * index_bits as u32;
        self.bits |= (index as u128) << shift;
        self.len = new_len;

        Ok(())
    }

    pub fn index(&self, depth: u8) -> Option<usize> {
        if depth >= self.len {
            return None;
        }

        let index_bits = TableGeometry::<F, G>::index_bits();
        let shift = depth as u32 * index_bits as u32;
        let mask = TableGeometry::<F, G>::index_mask() as u128;

        Some(((self.bits >> shift) & mask) as usize)
    }

    pub fn level_index(&self, root_level: Level, level: Level) -> Result<usize, AccessError> {
        if level.is_after(F::FINAL_LEVEL) {
            return Err(AccessError::InvalidTableLevel {
                root_level,
                level,
                final_level: F::FINAL_LEVEL,
            });
        }

        let distance = level
            .distance_from(root_level)
            .ok_or(AccessError::InvalidTableLevel {
                root_level,
                level,
                final_level: F::FINAL_LEVEL,
            })?;

        if distance >= self.len {
            return Err(AccessError::TablePathLevelUnavailable {
                root_level,
                level,
                len: self.len,
            });
        }

        self.index(distance)
            .ok_or(AccessError::TablePathLevelUnavailable {
                root_level,
                level,
                len: self.len,
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableAccessLocation<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub addr: TablePhysAddr<G>,
    pub root_level: Level,
    pub level: Level,
    pub path: TableWalkPath<F, G>,
}

impl<F, G> TableAccessLocation<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn root(addr: TablePhysAddr<G>, root_level: Level) -> Self {
        Self {
            addr,
            root_level,
            level: root_level,
            path: TableWalkPath::root(),
        }
    }

    pub fn child(
        addr: TablePhysAddr<G>,
        root_level: Level,
        level: Level,
        path: TableWalkPath<F, G>,
    ) -> Result<Self, AccessError> {
        if root_level.is_after(level) || level.is_after(F::FINAL_LEVEL) {
            return Err(AccessError::InvalidTableLevel {
                root_level,
                level,
                final_level: F::FINAL_LEVEL,
            });
        }

        let expected = level
            .distance_from(root_level)
            .ok_or(AccessError::InvalidTableLevel {
                root_level,
                level,
                final_level: F::FINAL_LEVEL,
            })?;

        if path.len() != expected {
            return Err(AccessError::TablePathLengthMismatch {
                expected,
                actual: path.len(),
            });
        }

        Ok(Self {
            addr,
            root_level,
            level,
            path,
        })
    }
}

pub unsafe trait TableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type Error;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error>;
}

pub unsafe trait TableAccessMut<F, G>: TableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error>;
}
