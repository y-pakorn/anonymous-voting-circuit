use std::marker::PhantomData;

use ark_crypto_primitives::encryption::elgamal::{constraints::OutputVar, SecretKey};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, CurveVar, EqGadget, GroupOpsBounds},
    ToBitsGadget,
};
use ark_relations::r1cs::ConstraintSynthesizer;

use crate::{
    elgamal::{AsymmetricDecryptionGadget, DecryptOutputVar, ElGamalDecGadget, SecretKeyVar},
    utils::ConstraintF,
};

pub struct ResultAnnouncementCircuitGeneric<C: ProjectiveCurve, CV: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Public
    pub decrypted_balance: ConstraintF<C>,
    pub encrypted_balance: (C::Affine, C::Affine),

    // Secret
    pub decrypted_balance_affine: C::Affine,
    pub elg_sk: SecretKey<C>,

    // Utils
    pub _p: PhantomData<CV>,
}

impl<C: ProjectiveCurve, CV: CurveVar<C, ConstraintF<C>>> ConstraintSynthesizer<ConstraintF<C>>
    for ResultAnnouncementCircuitGeneric<C, CV>
where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF<C>>,
    ) -> ark_relations::r1cs::Result<()> {
        let generator_var: CV = <CV as AllocVar<_, _>>::new_constant(
            cs.clone(),
            <C::Affine as AffineCurve>::prime_subgroup_generator(),
        )?;

        let decrypted_balance_var = FpVar::new_input(cs.clone(), || Ok(self.decrypted_balance))?;
        let encrypted_balance_var: OutputVar<_, _> =
            OutputVar::<C, CV>::new_input(cs.clone(), || Ok(self.encrypted_balance))?;

        let decrypted_output_var: DecryptOutputVar<_, _> =
            DecryptOutputVar::<C, CV>::new_witness(cs.clone(), || {
                Ok(self.decrypted_balance_affine)
            })?;
        let sk_var = SecretKeyVar::new_witness(cs.clone(), || Ok(self.elg_sk))?;
        let decrypted_calculated = ElGamalDecGadget::decrypt(&encrypted_balance_var, &sk_var)?;

        decrypted_output_var.decrypted.enforce_equal(
            &generator_var.scalar_mul_le(decrypted_balance_var.to_bits_le()?.iter())?,
        )?;
        decrypted_output_var.enforce_equal(&decrypted_calculated)?;

        Ok(())
    }
}
