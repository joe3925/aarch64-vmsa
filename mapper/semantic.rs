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

pub fn map_semantic_leaf<F, R, G, A, P, M, Codec, Cfg>(
    mapper: &mut Mapper<F, R, G, A, P, M>,
    config: &Cfg,
    input: WalkInputAddr,
    output: PhysAddr,
    level: Level,
    leaf_attrs: Codec::SemanticLeaf,
    table_attrs: Codec::SemanticTable,
) -> Result<MapLeafOutcome, SemanticMapperError<A::Error, P::Error>>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccessMut<F, G>,
    P: TableFrameProvider<G>,
    M: MapperMode<F, G>,
    Codec: AttributeCodec<
            F,
            R,
            G,
            Cfg,
            RawLeaf = LeafFieldsOf<F, R, G>,
            RawTable = TableFieldsOf<F, R, G>,
        >,
    LayoutOf<F, R, G>: DescriptorLayout<F, StageOf<R>, G>,
    LeafFieldsOf<F, R, G>: Copy,
{
    let leaf =
        Codec::resolve_leaf(config, level, leaf_attrs).map_err(SemanticMapperError::Attribute)?;
    let table =
        Codec::resolve_table(config, level, table_attrs).map_err(SemanticMapperError::Attribute)?;
    mapper
        .map_leaf(input, output, level, leaf, table)
        .map_err(SemanticMapperError::Mapper)
}

pub fn decode_semantic_leaf<F, R, G, Codec, Cfg>(
    config: &Cfg,
    level: Level,
    raw: LeafFieldsOf<F, R, G>,
) -> Result<Codec::SemanticLeaf, AttrError>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    Codec: AttributeCodec<
            F,
            R,
            G,
            Cfg,
            RawLeaf = LeafFieldsOf<F, R, G>,
            RawTable = TableFieldsOf<F, R, G>,
        >,
    LayoutOf<F, R, G>: DescriptorLayout<F, StageOf<R>, G>,
{
    Codec::decode_leaf(config, level, raw)
}

pub fn decode_semantic_table<F, R, G, Codec, Cfg>(
    config: &Cfg,
    level: Level,
    raw: TableFieldsOf<F, R, G>,
) -> Result<Codec::SemanticTable, AttrError>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    Codec: AttributeCodec<
            F,
            R,
            G,
            Cfg,
            RawLeaf = LeafFieldsOf<F, R, G>,
            RawTable = TableFieldsOf<F, R, G>,
        >,
    LayoutOf<F, R, G>: DescriptorLayout<F, StageOf<R>, G>,
{
    Codec::decode_table(config, level, raw)
}
