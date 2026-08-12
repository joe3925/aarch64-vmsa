use crate::address::TranslationGranule;
use crate::arch::{FeatureRequirements, VmsaFeatures};
use crate::attrs::{
    El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions, FixedNonSecurePas,
    FixedRealmIpaPas, NonSecureIpaContext, PasModel, PrivilegeModel, RealmIpaContext,
    RealmOrNonSecurePaPas, RootExtendedPas, SecureIpaContext, SecureNonSecureIpaContext,
    SecureSelectablePas, Stage2PermissionModel,
};
use crate::config::regime::{
    NonSecureEl1Stage1, NonSecureEl2HostStage1, NonSecureEl2Stage1, NonSecureEl2Stage2,
    RealmEl1Stage1, RealmEl2HostStage1, RealmEl2Stage1, RealmEl2Stage2, RootEl3Stage1,
    SecureEl1Stage1, SecureEl2HostStage1, SecureEl2NonSecureIpaStage2, SecureEl2SecureIpaStage2,
    SecureEl2Stage1,
};
use crate::descriptor::{DescriptorFormat, DescriptorLayout, HasLayout};
use crate::translation::{Stage1, Stage2, TranslationStage};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RegimeOwner {
    El1,
    El2,
    El3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TranslationSpace {
    NonSecure,
    Secure,
    Root,
    Realm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum IpaSpace {
    NonSecure,
    Secure,
    Realm,
}

mod private {
    pub trait Sealed {}
}

pub trait TranslationRegime: private::Sealed + Copy + 'static {
    type Stage: TranslationStage;
    type PasModel: PasModel;

    const OWNER: RegimeOwner;
    const SPACE: TranslationSpace;
    const REQUIRED_FEATURES: FeatureRequirements;
}

pub trait Stage1Regime: TranslationRegime {
    type PrivilegeModel: PrivilegeModel;

    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
}

pub trait Stage2Regime: TranslationRegime {
    type PermissionModel: Stage2PermissionModel;

    const IPA_SPACE: IpaSpace;
}

pub(crate) type RegimeLayout<F, R, G> =
    <F as HasLayout<<R as TranslationRegime>::Stage, G>>::Layout;

pub type RegimeLeafFields<F, R, G> =
    <<F as HasLayout<<R as TranslationRegime>::Stage, G>>::Layout as DescriptorLayout<
        <R as TranslationRegime>::Stage,
        G,
    >>::LeafFields;

pub type RegimeTableFields<F, R, G> =
    <<F as HasLayout<<R as TranslationRegime>::Stage, G>>::Layout as DescriptorLayout<
        <R as TranslationRegime>::Stage,
        G,
    >>::TableFields;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegimeValidationError {
    UnsupportedFeaturesOrSecurityState,
}

pub fn validate_regime<R: TranslationRegime>(
    features: &VmsaFeatures,
) -> Result<(), RegimeValidationError> {
    if features.verify(R::REQUIRED_FEATURES) {
        Ok(())
    } else {
        Err(RegimeValidationError::UnsupportedFeaturesOrSecurityState)
    }
}

pub fn validate_regime_format<F, R, G>(features: &VmsaFeatures) -> Result<(), RegimeValidationError>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    let required = R::REQUIRED_FEATURES
        .union(<RegimeLayout<F, R, G> as DescriptorLayout<R::Stage, G>>::REQUIRED_FEATURES);
    if features.verify(required) {
        Ok(())
    } else {
        Err(RegimeValidationError::UnsupportedFeaturesOrSecurityState)
    }
}

macro_rules! stage1_regime {
    ($name:ident, $owner:expr, $space:expr, $permissions:ty, $pas:ty) => {
        impl private::Sealed for $name {}
        impl TranslationRegime for $name {
            type Stage = Stage1;
            type PasModel = $pas;
            const OWNER: RegimeOwner = $owner;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements =
                <$permissions as PrivilegeModel>::REQUIRED_FEATURES
                    .union(<$pas as PasModel>::REQUIRED_FEATURES);
        }
        impl Stage1Regime for $name {
            type PrivilegeModel = $permissions;
            const SUPPORTS_EL0: bool = <$permissions as PrivilegeModel>::SUPPORTS_EL0;
            const HAS_TTBR1: bool = <$permissions as PrivilegeModel>::HAS_TTBR1;
        }
    };
}

stage1_regime!(
    NonSecureEl1Stage1,
    RegimeOwner::El1,
    TranslationSpace::NonSecure,
    El1And0Permissions,
    FixedNonSecurePas
);
stage1_regime!(
    SecureEl1Stage1,
    RegimeOwner::El1,
    TranslationSpace::Secure,
    El1And0Permissions,
    SecureSelectablePas
);
stage1_regime!(
    RealmEl1Stage1,
    RegimeOwner::El1,
    TranslationSpace::Realm,
    El1And0Permissions,
    FixedRealmIpaPas
);
stage1_regime!(
    NonSecureEl2Stage1,
    RegimeOwner::El2,
    TranslationSpace::NonSecure,
    El2Permissions,
    FixedNonSecurePas
);
stage1_regime!(
    SecureEl2Stage1,
    RegimeOwner::El2,
    TranslationSpace::Secure,
    El2Permissions,
    SecureSelectablePas
);
stage1_regime!(
    RealmEl2Stage1,
    RegimeOwner::El2,
    TranslationSpace::Realm,
    El2Permissions,
    RealmOrNonSecurePaPas
);
stage1_regime!(
    NonSecureEl2HostStage1,
    RegimeOwner::El2,
    TranslationSpace::NonSecure,
    El2And0Permissions,
    FixedNonSecurePas
);
stage1_regime!(
    SecureEl2HostStage1,
    RegimeOwner::El2,
    TranslationSpace::Secure,
    El2And0Permissions,
    SecureSelectablePas
);
stage1_regime!(
    RealmEl2HostStage1,
    RegimeOwner::El2,
    TranslationSpace::Realm,
    El2And0Permissions,
    RealmOrNonSecurePaPas
);
stage1_regime!(
    RootEl3Stage1,
    RegimeOwner::El3,
    TranslationSpace::Root,
    El3Permissions,
    RootExtendedPas
);

macro_rules! stage2_regime {
    ($name:ident, $context:ty, $space:expr, $ipa:expr) => {
        impl<P: Stage2PermissionModel> private::Sealed for $name<P> {}
        impl<P: Stage2PermissionModel> TranslationRegime for $name<P> {
            type Stage = Stage2;
            type PasModel = $context;
            const OWNER: RegimeOwner = RegimeOwner::El2;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements =
                P::REQUIRED_FEATURES.union(<$context as PasModel>::REQUIRED_FEATURES);
        }
        impl<P: Stage2PermissionModel> Stage2Regime for $name<P> {
            type PermissionModel = P;
            const IPA_SPACE: IpaSpace = $ipa;
        }
    };
}

stage2_regime!(
    NonSecureEl2Stage2,
    NonSecureIpaContext,
    TranslationSpace::NonSecure,
    IpaSpace::NonSecure
);
stage2_regime!(
    SecureEl2SecureIpaStage2,
    SecureIpaContext,
    TranslationSpace::Secure,
    IpaSpace::Secure
);
stage2_regime!(
    SecureEl2NonSecureIpaStage2,
    SecureNonSecureIpaContext,
    TranslationSpace::Secure,
    IpaSpace::NonSecure
);
stage2_regime!(
    RealmEl2Stage2,
    RealmIpaContext,
    TranslationSpace::Realm,
    IpaSpace::Realm
);
