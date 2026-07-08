use crate::format::DescriptorFormat;
use crate::granule::{Level, TranslationGranule};

use super::{RootTable, TablePhysAddr, TranslationTable, TranslationTableMut};

pub unsafe trait TableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type Error;

    fn table_at<'a>(
        &'a self,
        addr: TablePhysAddr<G>,
        level: Level,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error>;

    fn root_table<'a>(
        &'a self,
        root: RootTable<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        self.table_at(root.addr(), root.level())
    }
}

pub unsafe trait TableAccessMut<F, G>: TableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        addr: TablePhysAddr<G>,
        level: Level,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error>;

    fn root_table_mut<'a>(
        &'a mut self,
        root: RootTable<F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        self.table_at_mut(root.addr(), root.level())
    }
}
