use crate::address::{Level, PhysAddr, TranslationGranule};
use crate::attrs::{AttrError, AttributeCodec};
use crate::descriptor::{DescriptorFormat, DescriptorLayout, HasLayout};
use crate::regime::{LayoutOf, LeafFieldsOf, StageOf, TableFieldsOf, TranslationRegime};
use crate::table::{TableAccessMut, TableFrameProvider};
use crate::translation::walk::WalkInputAddr;

use super::{MapLeafOutcome, Mapper, MapperError, MapperMode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticMapperError<AccessErrorKind, FrameErrorKind> {
    Attribute(AttrError),
    Mapper(MapperError<AccessErrorKind, FrameErrorKind>),
}

pub fn map_semantic_leaf<F, R, G, A, P, M, Cfg>(
    mapper: &mut Mapper<F, R, G, A, P, M>,
    config: &Cfg,
    input: WalkInputAddr,
    output: PhysAddr,
    level: Level,
    leaf_attrs: <F as AttributeCodec<R, G, Cfg>>::SemanticLeaf,
    table_attrs: <F as AttributeCodec<R, G, Cfg>>::SemanticTable,
) -> Result<MapLeafOutcome, SemanticMapperError<A::Error, P::Error>>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccessMut<F, G>,
    P: TableFrameProvider<G>,
    M: MapperMode<F, G>,
    F: AttributeCodec<
            R,
            G,
            Cfg,
            RawLeaf = LeafFieldsOf<F, R, G>,
            RawTable = TableFieldsOf<F, R, G>,
        >,
    LayoutOf<F, R, G>: DescriptorLayout<StageOf<R>, G, Format = F>,
    LeafFieldsOf<F, R, G>: Copy,
{
    let leaf =
        F::resolve_leaf(config, level, leaf_attrs).map_err(SemanticMapperError::Attribute)?;
    let table =
        F::resolve_table(config, level, table_attrs).map_err(SemanticMapperError::Attribute)?;
    mapper
        .map_leaf(input, output, level, leaf, table)
        .map_err(SemanticMapperError::Mapper)
}

pub fn decode_semantic_leaf<F, R, G, Cfg>(
    config: &Cfg,
    level: Level,
    raw: LeafFieldsOf<F, R, G>,
) -> Result<<F as AttributeCodec<R, G, Cfg>>::SemanticLeaf, AttrError>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    F: AttributeCodec<
            R,
            G,
            Cfg,
            RawLeaf = LeafFieldsOf<F, R, G>,
            RawTable = TableFieldsOf<F, R, G>,
        >,
    LayoutOf<F, R, G>: DescriptorLayout<StageOf<R>, G, Format = F>,
{
    F::decode_leaf(config, level, raw)
}

pub fn decode_semantic_table<F, R, G, Cfg>(
    config: &Cfg,
    level: Level,
    raw: TableFieldsOf<F, R, G>,
) -> Result<<F as AttributeCodec<R, G, Cfg>>::SemanticTable, AttrError>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    F: AttributeCodec<
            R,
            G,
            Cfg,
            RawLeaf = LeafFieldsOf<F, R, G>,
            RawTable = TableFieldsOf<F, R, G>,
        >,
    LayoutOf<F, R, G>: DescriptorLayout<StageOf<R>, G, Format = F>,
{
    F::decode_table(config, level, raw)
}
