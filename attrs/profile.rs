use core::marker::PhantomData;

use crate::features::VmsaFeatures;
use crate::translation_regime::{IpaSpace, RegimeOwner, TranslationSpace};
use crate::walkers::{Stage1, Stage2, TranslationStage};

use super::{PermissionModel, Stage1PasModel, Stage2PasContext};

pub trait AttributeProfile<S>: Copy + 'static
where
    S: TranslationStage,
{
    const OWNER: RegimeOwner;
    const SPACE: TranslationSpace;
    const IPA_SPACE: Option<IpaSpace>;
    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
    const REQUIRED_FEATURES: VmsaFeatures;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1Profile<P, A>(PhantomData<fn() -> (P, A)>);

impl<P, A> AttributeProfile<Stage1> for Stage1Profile<P, A>
where
    P: PermissionModel,
    A: Stage1PasModel,
{
    const OWNER: RegimeOwner = P::OWNER;
    const SPACE: TranslationSpace = A::SPACE;
    const IPA_SPACE: Option<IpaSpace> = None;
    const SUPPORTS_EL0: bool = P::SUPPORTS_EL0;
    const HAS_TTBR1: bool = P::HAS_TTBR1;
    const REQUIRED_FEATURES: VmsaFeatures =
        P::REQUIRED_FEATURES
            .union(A::REQUIRED_FEATURES)
            .union(match (P::OWNER, A::SPACE) {
                (RegimeOwner::El2, TranslationSpace::Secure) => VmsaFeatures::NONE.with_sel2(),
                _ => VmsaFeatures::NONE,
            });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Profile<P, C>(PhantomData<fn() -> (P, C)>);

impl<P, C> AttributeProfile<Stage2> for Stage2Profile<P, C>
where
    P: PermissionModel,
    C: Stage2PasContext,
{
    const OWNER: RegimeOwner = P::OWNER;
    const SPACE: TranslationSpace = C::SPACE;
    const IPA_SPACE: Option<IpaSpace> = Some(C::IPA_SPACE);
    const SUPPORTS_EL0: bool = P::SUPPORTS_EL0;
    const HAS_TTBR1: bool = P::HAS_TTBR1;
    const REQUIRED_FEATURES: VmsaFeatures = P::REQUIRED_FEATURES.union(C::REQUIRED_FEATURES);
}
