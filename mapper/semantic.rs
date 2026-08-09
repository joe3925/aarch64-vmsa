use crate::address::{Level, PhysAddr, TranslationGranule};
use crate::attrs::{AttrError, AttributeCodec, SemanticLeafAttrs, SemanticTableAttrs};
use crate::descriptor::{DescriptorFormat, HasLayout};
use crate::regime::{RegimeLeafFields, RegimeTableFields, TranslationRegime};
use crate::table::{TableAccessMut, TableFrameProvider};
use crate::translation::walk::WalkInputAddr;

use super::{MapLeafOutcome, Mapper, MapperError, MapperMode, Mapping};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticMapperError<AccessErrorKind, FrameErrorKind> {
    Attribute(AttrError),
    Mapper(MapperError<AccessErrorKind, FrameErrorKind>),
}

impl<F, R, G, A, P, M> Mapper<F, R, G, A, P, M>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccessMut<F, G>,
    P: TableFrameProvider<G>,
    M: MapperMode<F, G>,
    RegimeLeafFields<F, R, G>: Copy,
{
    /// Encodes attributes and adds a mapping to an invalid entry.
    ///
    /// This function does not make the mapped address safe to access.
    pub fn map_semantic_leaf<Cfg>(
        &mut self,
        config: &Cfg,
        input: WalkInputAddr,
        output: PhysAddr,
        level: Level,
        leaf_attrs: SemanticLeafAttrs<F, R>,
        table_attrs: SemanticTableAttrs<F, R>,
    ) -> Result<MapLeafOutcome, SemanticMapperError<A::Error, P::Error>>
    where
        F: AttributeCodec<R, G, Cfg>,
    {
        let leaf = <F as AttributeCodec<R, G, Cfg>>::encode_leaf(config, level, leaf_attrs)
            .map_err(SemanticMapperError::Attribute)?;
        let table = <F as AttributeCodec<R, G, Cfg>>::encode_table(config, level, table_attrs)
            .map_err(SemanticMapperError::Attribute)?;
        self.map_leaf(input, output, level, leaf, table)
            .map_err(SemanticMapperError::Mapper)
    }
}

impl<F, R, G> Mapping<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    /// Decodes this mapping's raw leaf fields using the supplied architectural configuration.
    pub fn semantic_attrs<Cfg>(&self, config: &Cfg) -> Result<SemanticLeafAttrs<F, R>, AttrError>
    where
        F: AttributeCodec<R, G, Cfg>,
    {
        <F as AttributeCodec<R, G, Cfg>>::decode_leaf(config, self.level(), *self.fields())
    }
}

pub fn decode_semantic_leaf<F, R, G, Cfg>(
    config: &Cfg,
    level: Level,
    raw: RegimeLeafFields<F, R, G>,
) -> Result<SemanticLeafAttrs<F, R>, AttrError>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    F: AttributeCodec<R, G, Cfg>,
{
    <F as AttributeCodec<R, G, Cfg>>::decode_leaf(config, level, raw)
}

pub fn decode_semantic_table<F, R, G, Cfg>(
    config: &Cfg,
    level: Level,
    raw: RegimeTableFields<F, R, G>,
) -> Result<SemanticTableAttrs<F, R>, AttrError>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    F: AttributeCodec<R, G, Cfg>,
{
    <F as AttributeCodec<R, G, Cfg>>::decode_table(config, level, raw)
}
