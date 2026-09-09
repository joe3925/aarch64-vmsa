use crate::address::{Level, TranslationGranule};
use crate::attrs::{AttrError, SemanticAttributeTypes, SemanticLeafAttrs, SemanticTableAttrs};
use crate::descriptor::DescriptorFormat;
use crate::regime::{
    HasRegimeLayout, InterpretedLeafFields, InterpretedTableFields, TranslationRegime,
};
use crate::translation::TranslationStage;

/// Converts between semantic attributes and the raw fields selected by a format and regime.
/// Implemented on [`Stage1`](crate::translation::Stage1) and
/// [`Stage2`](crate::translation::Stage2) to keep stage dispatch coherent.
pub trait AttributeCodec<F, R, G, Cfg>: TranslationStage
where
    F: DescriptorFormat + HasRegimeLayout<R, G> + SemanticAttributeTypes<Self, R>,
    R: TranslationRegime<Stage = Self>,
    G: TranslationGranule,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<F, R>,
    ) -> Result<InterpretedLeafFields<F, R, G>, AttrError>;

    fn encode_table(
        config: &Cfg,
        level: Level,
        attrs: SemanticTableAttrs<F, R>,
    ) -> Result<InterpretedTableFields<F, R, G>, AttrError>;

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: InterpretedLeafFields<F, R, G>,
    ) -> Result<SemanticLeafAttrs<F, R>, AttrError>;

    fn decode_table(
        config: &Cfg,
        level: Level,
        raw: InterpretedTableFields<F, R, G>,
    ) -> Result<SemanticTableAttrs<F, R>, AttrError>;
}
