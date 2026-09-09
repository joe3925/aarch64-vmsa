use crate::address::{Level, TranslationGranule};
use crate::attrs::{
    AttrError, AttributeCodec, SemanticAttributeTypes, SemanticLeafAttrs, SemanticTableAttrs,
};
use crate::descriptor::DescriptorFormat;
use crate::regime::{
    HasRegimeLayout, InterpretedLeafFields, InterpretedTableFields, TranslationRegime,
};
use crate::table::{TableAccessMut, TableFrameProvider};
use crate::translation::walk::{WalkInputAddr, WalkOutputAddr};
use crate::translation::{WalkLeaf, WalkTable};

use super::{MapLeafOutcome, Mapper, MapperError, MapperMode, Mapping};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticMapperError<AccessErrorKind, FrameErrorKind> {
    Attribute(AttrError),
    Mapper(MapperError<AccessErrorKind, FrameErrorKind>),
}

impl<F, R, G, A, P, M> Mapper<F, R, G, A, P, M>
where
    F: DescriptorFormat + HasRegimeLayout<R, G> + SemanticAttributeTypes<R::Stage, R>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccessMut<F, G>,
    P: TableFrameProvider<G>,
    M: MapperMode<F, G>,
    InterpretedLeafFields<F, R, G>: Copy,
{
    /// This function encodes attributes and adds a mapping to an invalid entry.
    ///
    /// This function does not make access to the mapped address safe.
    pub fn map_semantic_leaf<Cfg>(
        &mut self,
        config: &Cfg,
        input: WalkInputAddr,
        output: WalkOutputAddr,
        level: Level,
        leaf_attrs: SemanticLeafAttrs<F, R>,
        table_attrs: SemanticTableAttrs<F, R>,
    ) -> Result<MapLeafOutcome, SemanticMapperError<A::Error, P::Error>>
    where
        R::Stage: AttributeCodec<F, R, G, Cfg>,
    {
        let leaf =
            <R::Stage as AttributeCodec<F, R, G, Cfg>>::encode_leaf(config, level, leaf_attrs)
                .map_err(SemanticMapperError::Attribute)?;
        let table =
            <R::Stage as AttributeCodec<F, R, G, Cfg>>::encode_table(config, level, table_attrs)
                .map_err(SemanticMapperError::Attribute)?;
        self.map_leaf(input, output, level, leaf, table)
            .map_err(SemanticMapperError::Mapper)
    }
}

impl<F, R, G> Mapping<F, R, G>
where
    F: DescriptorFormat + HasRegimeLayout<R, G> + SemanticAttributeTypes<R::Stage, R>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    /// This function decodes the raw leaf fields of this mapping with the specified architectural
    /// configuration.
    pub fn semantic_attrs<Cfg>(&self, config: &Cfg) -> Result<SemanticLeafAttrs<F, R>, AttrError>
    where
        R::Stage: AttributeCodec<F, R, G, Cfg>,
    {
        <R::Stage as AttributeCodec<F, R, G, Cfg>>::decode_leaf(
            config,
            self.level(),
            *self.fields(),
        )
    }
}

impl<F, R, G> WalkLeaf<F, R, G>
where
    F: DescriptorFormat + HasRegimeLayout<R, G> + SemanticAttributeTypes<R::Stage, R>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    /// This function decodes the raw fields of this leaf descriptor with the specified
    /// architectural configuration.
    pub fn semantic_attrs<Cfg>(&self, config: &Cfg) -> Result<SemanticLeafAttrs<F, R>, AttrError>
    where
        R::Stage: AttributeCodec<F, R, G, Cfg>,
    {
        <R::Stage as AttributeCodec<F, R, G, Cfg>>::decode_leaf(
            config,
            self.info().level(),
            *self.fields(),
        )
    }
}

impl<F, R, G> WalkTable<F, R, G>
where
    F: DescriptorFormat + HasRegimeLayout<R, G> + SemanticAttributeTypes<R::Stage, R>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    /// This function decodes the raw fields of this table descriptor with the specified
    /// architectural configuration.
    pub fn semantic_attrs<Cfg>(&self, config: &Cfg) -> Result<SemanticTableAttrs<F, R>, AttrError>
    where
        R::Stage: AttributeCodec<F, R, G, Cfg>,
    {
        <R::Stage as AttributeCodec<F, R, G, Cfg>>::decode_table(
            config,
            self.info().level(),
            *self.fields(),
        )
    }
}

pub fn decode_semantic_leaf<F, R, G, Cfg>(
    config: &Cfg,
    level: Level,
    raw: InterpretedLeafFields<F, R, G>,
) -> Result<SemanticLeafAttrs<F, R>, AttrError>
where
    F: DescriptorFormat + HasRegimeLayout<R, G> + SemanticAttributeTypes<R::Stage, R>,
    R: TranslationRegime,
    G: TranslationGranule,
    R::Stage: AttributeCodec<F, R, G, Cfg>,
{
    <R::Stage as AttributeCodec<F, R, G, Cfg>>::decode_leaf(config, level, raw)
}

pub fn decode_semantic_table<F, R, G, Cfg>(
    config: &Cfg,
    level: Level,
    raw: InterpretedTableFields<F, R, G>,
) -> Result<SemanticTableAttrs<F, R>, AttrError>
where
    F: DescriptorFormat + HasRegimeLayout<R, G> + SemanticAttributeTypes<R::Stage, R>,
    R: TranslationRegime,
    G: TranslationGranule,
    R::Stage: AttributeCodec<F, R, G, Cfg>,
{
    <R::Stage as AttributeCodec<F, R, G, Cfg>>::decode_table(config, level, raw)
}
