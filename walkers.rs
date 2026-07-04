#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TranslationStageKind {
    Stage1,
    Stage2,
}

pub trait TranslationStage: Copy + 'static {
    const KIND: TranslationStageKind;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2;

impl TranslationStage for Stage1 {
    const KIND: TranslationStageKind = TranslationStageKind::Stage1;
}

impl TranslationStage for Stage2 {
    const KIND: TranslationStageKind = TranslationStageKind::Stage2;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WalkProfileKind {
    Stage1,
    Stage2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AddressKind {
    Va,
    Ipa,
    Pa,
}

pub trait TranslationWalkProfile: Copy + 'static {
    type Stage: TranslationStage;

    const KIND: WalkProfileKind;
    const INPUT_ADDRESS_KIND: AddressKind;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1Walk;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Walk;

impl TranslationWalkProfile for Stage1Walk {
    type Stage = Stage1;

    const KIND: WalkProfileKind = WalkProfileKind::Stage1;
    const INPUT_ADDRESS_KIND: AddressKind = AddressKind::Va;
}

impl TranslationWalkProfile for Stage2Walk {
    type Stage = Stage2;

    const KIND: WalkProfileKind = WalkProfileKind::Stage2;
    const INPUT_ADDRESS_KIND: AddressKind = AddressKind::Ipa;
}
