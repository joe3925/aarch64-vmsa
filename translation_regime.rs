#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RegimeOwner {
    El1,
    El2,
    El3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TranslationStage {
    Stage1,
    Stage2,
}

pub trait TranslationRegime: Copy + 'static {
    const OWNER: RegimeOwner;
    const STAGE: TranslationStage;

    const SUPPORTS_EL0: bool =
        matches!(Self::OWNER, RegimeOwner::El1) && matches!(Self::STAGE, TranslationStage::Stage1);

    const HAS_TTBR1: bool =
        matches!(Self::OWNER, RegimeOwner::El1) && matches!(Self::STAGE, TranslationStage::Stage1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El2Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El2Stage2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El3Stage1;

impl TranslationRegime for El1Stage1 {
    const OWNER: RegimeOwner = RegimeOwner::El1;
    const STAGE: TranslationStage = TranslationStage::Stage1;
}

impl TranslationRegime for El2Stage1 {
    const OWNER: RegimeOwner = RegimeOwner::El2;
    const STAGE: TranslationStage = TranslationStage::Stage1;
}

impl TranslationRegime for El2Stage2 {
    const OWNER: RegimeOwner = RegimeOwner::El2;
    const STAGE: TranslationStage = TranslationStage::Stage2;
}

impl TranslationRegime for El3Stage1 {
    const OWNER: RegimeOwner = RegimeOwner::El3;
    const STAGE: TranslationStage = TranslationStage::Stage1;
}
