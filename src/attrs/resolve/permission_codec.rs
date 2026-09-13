use core::marker::PhantomData;

use crate::attrs::{AttrError, PrivilegeModel, Stage2PermissionModel};
use crate::descriptor::{
    DescriptorInterpretation, PeDescriptors, SmmuV2Descriptors, SmmuV3Descriptors,
};

/// Converts between semantic permissions and a typed architectural permission encoding.
pub trait PermissionCodec<Cfg, Encoding> {
    type Permissions;

    fn encode(config: &Cfg, wanted: Self::Permissions) -> Result<Encoding, AttrError>;
    fn decode(config: &Cfg, encoding: Encoding) -> Result<Self::Permissions, AttrError>;
}

pub trait Stage1PermissionCodec {
    type Interpretation: DescriptorInterpretation;
    type PrivilegeModel: PrivilegeModel;
}

pub trait Stage2PermissionCodec {
    type Interpretation: DescriptorInterpretation;
    type PermissionModel: Stage2PermissionModel;
}

pub struct PeStage1PermissionCodec<P>(PhantomData<P>);
pub struct SmmuV2Stage1PermissionCodec<P>(PhantomData<P>);
pub struct SmmuV3Stage1PermissionCodec<P>(PhantomData<P>);
pub struct PeStage2PermissionCodec<P>(PhantomData<P>);
pub struct SmmuV2Stage2PermissionCodec<P>(PhantomData<P>);
pub struct SmmuV3Stage2PermissionCodec<P>(PhantomData<P>);

macro_rules! stage1_codec {
    ($codec:ident, $interpretation:ty) => {
        impl<P: PrivilegeModel> Stage1PermissionCodec for $codec<P> {
            type Interpretation = $interpretation;
            type PrivilegeModel = P;
        }
    };
}

stage1_codec!(PeStage1PermissionCodec, PeDescriptors);
stage1_codec!(SmmuV2Stage1PermissionCodec, SmmuV2Descriptors);
stage1_codec!(SmmuV3Stage1PermissionCodec, SmmuV3Descriptors);

macro_rules! stage2_codec {
    ($codec:ident, $interpretation:ty) => {
        impl<P: Stage2PermissionModel> Stage2PermissionCodec for $codec<P> {
            type Interpretation = $interpretation;
            type PermissionModel = P;
        }
    };
}

stage2_codec!(PeStage2PermissionCodec, PeDescriptors);
stage2_codec!(SmmuV2Stage2PermissionCodec, SmmuV2Descriptors);
stage2_codec!(SmmuV3Stage2PermissionCodec, SmmuV3Descriptors);
