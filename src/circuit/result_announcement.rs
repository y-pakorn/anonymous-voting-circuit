use std::marker::PhantomData;

use ark_crypto_primitives::encryption::elgamal::{constraints::OutputVar, SecretKey};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
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

pub type ResultAnnouncementCircuit =
    ResultAnnouncementCircuitGeneric<EdwardsProjective, EdwardsVar>;

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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_crypto_primitives::{
        encryption::{
            elgamal::{ElGamal, Randomness, SecretKey},
            AsymmetricEncryptionScheme,
        },
        CircuitSpecificSetupSNARK, SNARK,
    };
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_std::test_rng;

    use super::ResultAnnouncementCircuit;

    type MyEnc = ElGamal<EdwardsProjective>;

    #[test]
    #[ignore = "Long compute time ~14.41s"]
    fn result_announcement_verify() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        let parameters = MyEnc::setup(&mut rng)?;
        let (pk, sk) = MyEnc::keygen(&parameters, &mut rng)?;
        let fr = Fr::from(20);
        let fr_affine = EdwardsAffine::prime_subgroup_generator()
            .mul(fr)
            .into_affine();
        let randomness = Randomness::rand(&mut rng);
        let primitive_result = MyEnc::encrypt(&parameters, &pk, &fr_affine, &randomness)?;
        let primitive_decoded_result = MyEnc::decrypt(&parameters, &sk, &primitive_result)?;

        let (cpk, cvk) = Groth16::<Bls12_381>::setup(
            ResultAnnouncementCircuit {
                decrypted_balance: Fr::rand(&mut rng),
                encrypted_balance: (EdwardsAffine::rand(&mut rng), EdwardsAffine::rand(&mut rng)),
                decrypted_balance_affine: EdwardsAffine::rand(&mut rng),
                elg_sk: SecretKey(<EdwardsProjective as ProjectiveCurve>::ScalarField::rand(
                    &mut rng,
                )),
                _p: std::marker::PhantomData,
            },
            &mut rng,
        )?;

        let proof = Groth16::prove(
            &cpk,
            ResultAnnouncementCircuit {
                decrypted_balance: fr,
                decrypted_balance_affine: primitive_decoded_result,
                encrypted_balance: primitive_result,
                elg_sk: sk,
                _p: std::marker::PhantomData,
            },
            &mut rng,
        )?;

        let is_verified = Groth16::verify(
            &cvk,
            &[
                fr,
                primitive_result.0.x,
                primitive_result.0.y,
                primitive_result.1.x,
                primitive_result.1.y,
            ],
            &proof,
        )?;

        assert!(is_verified);

        Ok(())
    }
}
