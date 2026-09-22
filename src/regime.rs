use crate::address::ArmTranslationGranule;
use crate::arch::{FeatureRequirements, VmsaFeatures};
use crate::attrs::{
    El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions, FixedNonSecurePas,
    FixedRealmIpaPas, NonSecureIpaContext, PasModel, PeStage1PermissionCodec,
    PeStage2PermissionCodec, PrivilegeModel, RealmIpaContext, RealmOrNonSecurePaPas,
    RootExtendedPas, SecureIpaContext, SecureNonSecureIpaContext, SecureSelectablePas,
    SmmuPrivilegedStreamPermissions, SmmuStreamPermissions, SmmuV2Stage1PermissionCodec,
    SmmuV2Stage2PermissionCodec, SmmuV3Stage1PermissionCodec, SmmuV3Stage2PermissionCodec,
    Stage1PermissionCodec, Stage2PermissionCodec, Stage2PermissionModel,
};
use crate::config::format::{DescriptorEndian, Vmsa64};
use crate::config::regime::{
    NonSecureEl1Stage1, NonSecureEl2HostStage1, NonSecureEl2Stage1, NonSecureEl2Stage2,
    RealmEl1Stage1, RealmEl2HostStage1, RealmEl2Stage1, RealmEl2Stage2, RootEl3Stage1,
    SecureEl1Stage1, SecureEl2HostStage1, SecureEl2NonSecureIpaStage2, SecureEl2SecureIpaStage2,
    SecureEl2Stage1,
};
use crate::config::regime::{smmu_v2, smmu_v3};
use crate::config::stage2::StandardStage2PermissionModel;
use crate::descriptor::{
    ArmDescriptorFormat, ArmDescriptorLayout, DescriptorInterpretation, DescriptorLayout,
    HasLayout, InterpretsDescriptors, PeDescriptors, SmmuV2Descriptors, SmmuV3Descriptors,
};
use crate::translation::{Stage1, Stage2, TranslationStage};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RegimeOwner {
    El1,
    El2,
    El3,
    Smmu,
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
    type DescriptorInterpretation: DescriptorInterpretation;

    const OWNER: RegimeOwner;
    const SPACE: TranslationSpace;
    const REQUIRED_FEATURES: FeatureRequirements;
}

/// A PE-owned translation regime accepted by the PE feature validators.
pub trait PeTranslationRegime: TranslationRegime<DescriptorInterpretation = PeDescriptors> {}

pub trait Stage1Regime: TranslationRegime {
    type PermissionCodec: Stage1PermissionCodec<Interpretation = Self::DescriptorInterpretation>;

    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
}

pub type Stage1PrivilegeModel<R> =
    <<R as Stage1Regime>::PermissionCodec as Stage1PermissionCodec>::PrivilegeModel;

pub trait Stage2Regime: TranslationRegime {
    type PermissionCodec: Stage2PermissionCodec<Interpretation = Self::DescriptorInterpretation>;

    const IPA_SPACE: IpaSpace;
}

pub type Stage2PermissionModelOf<R> =
    <<R as Stage2Regime>::PermissionCodec as Stage2PermissionCodec>::PermissionModel;

pub trait HasRegimeLayout<R, G>: ArmDescriptorFormat
where
    R: TranslationRegime,
    G: ArmTranslationGranule,
{
    type Layout: ArmDescriptorLayout<G, Format = Self>;
}

impl<F, R, G> HasRegimeLayout<R, G> for F
where
    F: ArmDescriptorFormat + HasLayout<R::Stage, G>,
    R: PeTranslationRegime,
    G: ArmTranslationGranule,
{
    type Layout = <F as HasLayout<R::Stage, G>>::Layout;
}

/// Raw fields selected by the PE layout for `R`'s translation stage.
///
/// This preserves the original public alias for PE-oriented generic code. Use
/// [`InterpretedLeafFields`] when the regime's descriptor interpretation must be honored.
pub type RegimeLeafFields<F, R, G> =
    <<F as HasLayout<<R as TranslationRegime>::Stage, G>>::Layout as DescriptorLayout<G>>::LeafFields;

/// Raw leaf fields selected by the descriptor interpretation associated with `R`.
pub type InterpretedLeafFields<F, R, G> =
    <<F as HasRegimeLayout<R, G>>::Layout as DescriptorLayout<G>>::LeafFields;

/// Raw fields selected by the PE table layout for `R`'s translation stage.
pub type RegimeTableFields<F, R, G> =
    <<F as HasLayout<<R as TranslationRegime>::Stage, G>>::Layout as DescriptorLayout<G>>::TableFields;

/// Raw table fields selected by the descriptor interpretation associated with `R`.
pub type InterpretedTableFields<F, R, G> =
    <<F as HasRegimeLayout<R, G>>::Layout as DescriptorLayout<G>>::TableFields;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegimeValidationError {
    UnsupportedFeaturesOrSecurityState,
}

pub fn validate_regime<R: PeTranslationRegime>(
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
    F: ArmDescriptorFormat + HasRegimeLayout<R, G>,
    R: PeTranslationRegime,
    G: ArmTranslationGranule,
{
    let required = R::REQUIRED_FEATURES
        .union(<<F as HasRegimeLayout<R, G>>::Layout as ArmDescriptorLayout<G>>::REQUIRED_FEATURES);
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
            type DescriptorInterpretation = PeDescriptors;
            const OWNER: RegimeOwner = $owner;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements =
                <$permissions as PrivilegeModel>::REQUIRED_FEATURES
                    .union(<$pas as PasModel>::REQUIRED_FEATURES);
        }
        impl PeTranslationRegime for $name {}
        impl Stage1Regime for $name {
            type PermissionCodec = PeStage1PermissionCodec<$permissions>;
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
            type DescriptorInterpretation = PeDescriptors;
            const OWNER: RegimeOwner = RegimeOwner::El2;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements =
                P::REQUIRED_FEATURES.union(<$context as PasModel>::REQUIRED_FEATURES);
        }
        impl<P: Stage2PermissionModel> PeTranslationRegime for $name<P> {}
        impl<P: Stage2PermissionModel> Stage2Regime for $name<P> {
            type PermissionCodec = PeStage2PermissionCodec<P>;
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

macro_rules! smmu_stage1_regime {
    ($name:path, $interpretation:ty, $codec:ident, $space:expr, $permissions:ty, $pas:ty) => {
        impl private::Sealed for $name {}
        impl TranslationRegime for $name {
            type Stage = Stage1;
            type PasModel = $pas;
            type DescriptorInterpretation = $interpretation;
            const OWNER: RegimeOwner = RegimeOwner::Smmu;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
        }
        impl Stage1Regime for $name {
            type PermissionCodec = $codec<$permissions>;
            const SUPPORTS_EL0: bool = <$permissions as PrivilegeModel>::SUPPORTS_EL0;
            const HAS_TTBR1: bool = <$permissions as PrivilegeModel>::HAS_TTBR1;
        }
        impl<F, G> HasRegimeLayout<$name, G> for F
        where
            F: ArmDescriptorFormat,
            G: ArmTranslationGranule,
            $interpretation: InterpretsDescriptors<F, Stage1, G>,
        {
            type Layout = <$interpretation as InterpretsDescriptors<F, Stage1, G>>::Layout;
        }
    };
}

macro_rules! smmu_stage2_regime {
    ($name:ty, $interpretation:ty, $context:ty, $space:expr, $ipa:expr, $permissions:ty) => {
        impl private::Sealed for $name {}
        impl TranslationRegime for $name {
            type Stage = Stage2;
            type PasModel = $context;
            type DescriptorInterpretation = $interpretation;
            const OWNER: RegimeOwner = RegimeOwner::Smmu;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
        }
        impl Stage2Regime for $name {
            type PermissionCodec = SmmuV2Stage2PermissionCodec<$permissions>;
            const IPA_SPACE: IpaSpace = $ipa;
        }
    };
}

smmu_stage1_regime!(
    smmu_v2::NonSecureStreamStage1,
    SmmuV2Descriptors,
    SmmuV2Stage1PermissionCodec,
    TranslationSpace::NonSecure,
    SmmuStreamPermissions,
    FixedNonSecurePas
);
smmu_stage1_regime!(
    smmu_v2::NonSecurePrivilegedStreamStage1,
    SmmuV2Descriptors,
    SmmuV2Stage1PermissionCodec,
    TranslationSpace::NonSecure,
    SmmuPrivilegedStreamPermissions,
    FixedNonSecurePas
);
smmu_stage1_regime!(
    smmu_v2::SecureStreamStage1,
    SmmuV2Descriptors,
    SmmuV2Stage1PermissionCodec,
    TranslationSpace::Secure,
    SmmuStreamPermissions,
    SecureSelectablePas
);
smmu_stage1_regime!(
    smmu_v2::SecurePrivilegedStreamStage1,
    SmmuV2Descriptors,
    SmmuV2Stage1PermissionCodec,
    TranslationSpace::Secure,
    SmmuPrivilegedStreamPermissions,
    SecureSelectablePas
);
smmu_stage2_regime!(
    smmu_v2::NonSecureIpaStage2,
    SmmuV2Descriptors,
    NonSecureIpaContext,
    TranslationSpace::NonSecure,
    IpaSpace::NonSecure,
    StandardStage2PermissionModel
);

impl<E, G> HasRegimeLayout<smmu_v2::NonSecureIpaStage2, G> for Vmsa64<E>
where
    E: DescriptorEndian,
    G: ArmTranslationGranule,
{
    type Layout = crate::descriptor::format::SmmuV2Vmsa64Stage2Layout<E, G>;
}

smmu_stage1_regime!(
    smmu_v3::NonSecureStreamStage1,
    SmmuV3Descriptors,
    SmmuV3Stage1PermissionCodec,
    TranslationSpace::NonSecure,
    SmmuStreamPermissions,
    FixedNonSecurePas
);
smmu_stage1_regime!(
    smmu_v3::NonSecurePrivilegedStreamStage1,
    SmmuV3Descriptors,
    SmmuV3Stage1PermissionCodec,
    TranslationSpace::NonSecure,
    SmmuPrivilegedStreamPermissions,
    FixedNonSecurePas
);
smmu_stage1_regime!(
    smmu_v3::SecureStreamStage1,
    SmmuV3Descriptors,
    SmmuV3Stage1PermissionCodec,
    TranslationSpace::Secure,
    SmmuStreamPermissions,
    SecureSelectablePas
);
smmu_stage1_regime!(
    smmu_v3::SecurePrivilegedStreamStage1,
    SmmuV3Descriptors,
    SmmuV3Stage1PermissionCodec,
    TranslationSpace::Secure,
    SmmuPrivilegedStreamPermissions,
    SecureSelectablePas
);
smmu_stage1_regime!(
    smmu_v3::RealmStreamStage1,
    SmmuV3Descriptors,
    SmmuV3Stage1PermissionCodec,
    TranslationSpace::Realm,
    SmmuStreamPermissions,
    FixedRealmIpaPas
);
smmu_stage1_regime!(
    smmu_v3::RealmPrivilegedStreamStage1,
    SmmuV3Descriptors,
    SmmuV3Stage1PermissionCodec,
    TranslationSpace::Realm,
    SmmuPrivilegedStreamPermissions,
    RealmOrNonSecurePaPas
);

macro_rules! smmu_v3_stage2_regime {
    ($name:ident, $context:ty, $space:expr, $ipa:expr) => {
        impl<P: Stage2PermissionModel> private::Sealed for smmu_v3::$name<P> {}
        impl<P: Stage2PermissionModel> TranslationRegime for smmu_v3::$name<P> {
            type Stage = Stage2;
            type PasModel = $context;
            type DescriptorInterpretation = SmmuV3Descriptors;
            const OWNER: RegimeOwner = RegimeOwner::Smmu;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
        }
        impl<P: Stage2PermissionModel> Stage2Regime for smmu_v3::$name<P> {
            type PermissionCodec = SmmuV3Stage2PermissionCodec<P>;
            const IPA_SPACE: IpaSpace = $ipa;
        }
        impl<F, G, P> HasRegimeLayout<smmu_v3::$name<P>, G> for F
        where
            F: ArmDescriptorFormat,
            G: ArmTranslationGranule,
            P: Stage2PermissionModel,
            SmmuV3Descriptors: InterpretsDescriptors<F, Stage2, G>,
        {
            type Layout = <SmmuV3Descriptors as InterpretsDescriptors<F, Stage2, G>>::Layout;
        }
    };
}

smmu_v3_stage2_regime!(
    NonSecureIpaStage2,
    NonSecureIpaContext,
    TranslationSpace::NonSecure,
    IpaSpace::NonSecure
);
smmu_v3_stage2_regime!(
    SecureIpaStage2,
    SecureIpaContext,
    TranslationSpace::Secure,
    IpaSpace::Secure
);
smmu_v3_stage2_regime!(
    SecureStreamNonSecureIpaStage2,
    SecureNonSecureIpaContext,
    TranslationSpace::Secure,
    IpaSpace::NonSecure
);
smmu_v3_stage2_regime!(
    RealmIpaStage2,
    RealmIpaContext,
    TranslationSpace::Realm,
    IpaSpace::Realm
);

macro_rules! shared_regime {
    ($regime:ty) => {
        impl<F, G> paging::regime::TranslationRegime<F, G> for $regime
        where
            F: ArmDescriptorFormat + HasRegimeLayout<$regime, G>,
            G: ArmTranslationGranule,
        {
            type Layout = <F as HasRegimeLayout<$regime, G>>::Layout;
        }
    };
}

shared_regime!(NonSecureEl1Stage1);
shared_regime!(SecureEl1Stage1);
shared_regime!(RealmEl1Stage1);
shared_regime!(NonSecureEl2Stage1);
shared_regime!(SecureEl2Stage1);
shared_regime!(RealmEl2Stage1);
shared_regime!(NonSecureEl2HostStage1);
shared_regime!(SecureEl2HostStage1);
shared_regime!(RealmEl2HostStage1);
shared_regime!(RootEl3Stage1);
shared_regime!(smmu_v2::NonSecureStreamStage1);
shared_regime!(smmu_v2::NonSecurePrivilegedStreamStage1);
shared_regime!(smmu_v2::SecureStreamStage1);
shared_regime!(smmu_v2::SecurePrivilegedStreamStage1);
shared_regime!(smmu_v2::NonSecureIpaStage2);
shared_regime!(smmu_v3::NonSecureStreamStage1);
shared_regime!(smmu_v3::NonSecurePrivilegedStreamStage1);
shared_regime!(smmu_v3::SecureStreamStage1);
shared_regime!(smmu_v3::SecurePrivilegedStreamStage1);
shared_regime!(smmu_v3::RealmStreamStage1);
shared_regime!(smmu_v3::RealmPrivilegedStreamStage1);

macro_rules! shared_generic_regime {
    ($regime:ident) => {
        impl<F, G, P> paging::regime::TranslationRegime<F, G> for $regime<P>
        where
            F: ArmDescriptorFormat + HasRegimeLayout<$regime<P>, G>,
            G: ArmTranslationGranule,
            P: Stage2PermissionModel,
        {
            type Layout = <F as HasRegimeLayout<$regime<P>, G>>::Layout;
        }
    };
}

shared_generic_regime!(NonSecureEl2Stage2);
shared_generic_regime!(SecureEl2SecureIpaStage2);
shared_generic_regime!(SecureEl2NonSecureIpaStage2);
shared_generic_regime!(RealmEl2Stage2);

macro_rules! shared_generic_smmu_v3_regime {
    ($regime:ident) => {
        impl<F, G, P> paging::regime::TranslationRegime<F, G> for smmu_v3::$regime<P>
        where
            F: ArmDescriptorFormat + HasRegimeLayout<smmu_v3::$regime<P>, G>,
            G: ArmTranslationGranule,
            P: Stage2PermissionModel,
        {
            type Layout = <F as HasRegimeLayout<smmu_v3::$regime<P>, G>>::Layout;
        }
    };
}

shared_generic_smmu_v3_regime!(NonSecureIpaStage2);
shared_generic_smmu_v3_regime!(SecureIpaStage2);
shared_generic_smmu_v3_regime!(SecureStreamNonSecureIpaStage2);
shared_generic_smmu_v3_regime!(RealmIpaStage2);
