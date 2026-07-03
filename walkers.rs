#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TranslationStage {
    Stage1,
    Stage2,
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
    const KIND: WalkProfileKind;
    const STAGE: TranslationStage;

    const INPUT_ADDRESS_KIND: AddressKind;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1Walk;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Walk;

impl TranslationWalkProfile for Stage1Walk {
    const KIND: WalkProfileKind = WalkProfileKind::Stage1;
    const STAGE: TranslationStage = TranslationStage::Stage1;

    const INPUT_ADDRESS_KIND: AddressKind = AddressKind::Va;
}

impl TranslationWalkProfile for Stage2Walk {
    const KIND: WalkProfileKind = WalkProfileKind::Stage2;
    const STAGE: TranslationStage = TranslationStage::Stage2;

    const INPUT_ADDRESS_KIND: AddressKind = AddressKind::Ipa;
}
