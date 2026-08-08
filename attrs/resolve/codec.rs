use crate::address::{Level, TranslationGranule};
use crate::attrs::{AttrError, SemanticAttributeTypes, SemanticLeafAttrs, SemanticTableAttrs};
use crate::descriptor::{DescriptorFormat, HasLayout};
use crate::regime::{RegimeLeafFields, RegimeTableFields, TranslationRegime};
use crate::translation::TranslationStage;

/// Converts between the semantic attributes and raw fields selected by a format and regime.
pub trait AttributeCodec<R, G, Cfg>:
    DescriptorFormat
    + HasLayout<<R as TranslationRegime>::Stage, G>
    + SemanticAttributeTypes<<R as TranslationRegime>::Stage, R>
where
    R: TranslationRegime,
    G: TranslationGranule,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<Self, R>,
    ) -> Result<RegimeLeafFields<Self, R, G>, AttrError>;

    fn encode_table(
        config: &Cfg,
        level: Level,
        attrs: SemanticTableAttrs<Self, R>,
    ) -> Result<RegimeTableFields<Self, R, G>, AttrError>;

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: RegimeLeafFields<Self, R, G>,
    ) -> Result<SemanticLeafAttrs<Self, R>, AttrError>;

    fn decode_table(
        config: &Cfg,
        level: Level,
        raw: RegimeTableFields<Self, R, G>,
    ) -> Result<SemanticTableAttrs<Self, R>, AttrError>;
}

pub(super) trait AttributeCodecCell<F, R, G, Cfg>: TranslationStage
where
    F: DescriptorFormat + HasLayout<Self, G> + SemanticAttributeTypes<Self, R>,
    R: TranslationRegime<Stage = Self>,
    G: TranslationGranule,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<F, R>,
    ) -> Result<RegimeLeafFields<F, R, G>, AttrError>;

    fn encode_table(
        config: &Cfg,
        level: Level,
        attrs: SemanticTableAttrs<F, R>,
    ) -> Result<RegimeTableFields<F, R, G>, AttrError>;

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: RegimeLeafFields<F, R, G>,
    ) -> Result<SemanticLeafAttrs<F, R>, AttrError>;

    fn decode_table(
        config: &Cfg,
        level: Level,
        raw: RegimeTableFields<F, R, G>,
    ) -> Result<SemanticTableAttrs<F, R>, AttrError>;
}

impl<F, R, G, Cfg> AttributeCodec<R, G, Cfg> for F
where
    F: DescriptorFormat
        + HasLayout<<R as TranslationRegime>::Stage, G>
        + SemanticAttributeTypes<<R as TranslationRegime>::Stage, R>,
    R: TranslationRegime,
    G: TranslationGranule,
    R::Stage: AttributeCodecCell<F, R, G, Cfg>,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<Self, R>,
    ) -> Result<RegimeLeafFields<Self, R, G>, AttrError> {
        <R::Stage as AttributeCodecCell<F, R, G, Cfg>>::encode_leaf(config, level, attrs)
    }

    fn encode_table(
        config: &Cfg,
        level: Level,
        attrs: SemanticTableAttrs<Self, R>,
    ) -> Result<RegimeTableFields<Self, R, G>, AttrError> {
        <R::Stage as AttributeCodecCell<F, R, G, Cfg>>::encode_table(config, level, attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: RegimeLeafFields<Self, R, G>,
    ) -> Result<SemanticLeafAttrs<Self, R>, AttrError> {
        <R::Stage as AttributeCodecCell<F, R, G, Cfg>>::decode_leaf(config, level, raw)
    }

    fn decode_table(
        config: &Cfg,
        level: Level,
        raw: RegimeTableFields<Self, R, G>,
    ) -> Result<SemanticTableAttrs<Self, R>, AttrError> {
        <R::Stage as AttributeCodecCell<F, R, G, Cfg>>::decode_table(config, level, raw)
    }
}
