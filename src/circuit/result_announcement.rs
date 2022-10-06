use std::marker::PhantomData;

use ark_crypto_primitives::encryption::elgamal::{
    constraints::{OutputVar, PublicKeyVar},
    PublicKey, SecretKey,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, CurveVar, GroupOpsBounds},
    ToBitsGadget,
};
use ark_relations::r1cs::ConstraintSynthesizer;

use crate::{
    elgamal::{AsymmetricDecryptionGadget, ElGamalDecGadget, SecretKeyVar},
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
    pub param: C::Affine,
    pub pk: PublicKey<C>,

    // Secret
    pub sk: SecretKey<C>,

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
        let param_var = <CV as AllocVar<_, _>>::new_input(cs.clone(), || Ok(self.param))?;
        let pk_var = PublicKeyVar::<C, CV>::new_input(cs.clone(), || Ok(self.pk))?;

        let sk_var = SecretKeyVar::new_witness(cs, || Ok(self.sk))?;
        let decrypted_calculated = ElGamalDecGadget::decrypt(&encrypted_balance_var, &sk_var)?;

        pk_var
            .pk
            .enforce_equal(&param_var.scalar_mul_le(sk_var.0.to_bits_le()?.iter())?)?;
        decrypted_calculated.decrypted.enforce_equal(
            &generator_var.scalar_mul_le(decrypted_balance_var.to_bits_le()?.iter())?,
        )?;

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

        let (cpk, cvk) = Groth16::<Bls12_381>::setup(
            ResultAnnouncementCircuit {
                decrypted_balance: Fr::rand(&mut rng),
                encrypted_balance: (EdwardsAffine::rand(&mut rng), EdwardsAffine::rand(&mut rng)),
                sk: SecretKey(<EdwardsProjective as ProjectiveCurve>::ScalarField::rand(
                    &mut rng,
                )),
                _p: std::marker::PhantomData,
                pk: EdwardsAffine::rand(&mut rng),
                param: EdwardsAffine::rand(&mut rng),
            },
            &mut rng,
        )?;

        let proof = Groth16::prove(
            &cpk,
            ResultAnnouncementCircuit {
                decrypted_balance: fr,
                encrypted_balance: primitive_result,
                _p: std::marker::PhantomData,
                pk,
                sk,
                param: parameters.generator,
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
                parameters.generator.x,
                parameters.generator.y,
                pk.x,
                pk.y,
            ],
            &proof,
        )?;

        assert!(is_verified);

        Ok(())
    }
}
