use std::marker::PhantomData;

use ark_crypto_primitives::encryption::elgamal::{constraints::PublicKeyVar, PublicKey, SecretKey};
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::{
    prelude::{AllocVar, CurveVar, GroupOpsBounds},
    ToBitsGadget,
};
use ark_relations::r1cs::ConstraintSynthesizer;

use crate::{elgamal::SecretKeyVar, utils::ConstraintF};

pub type ProposalCreationCircuit = ProposalCreationCircuitGeneric<EdwardsProjective, EdwardsVar>;

pub struct ProposalCreationCircuitGeneric<C: ProjectiveCurve, CV: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Public
    pub param: C::Affine,
    pub pk: PublicKey<C>,

    // Secret
    pub sk: SecretKey<C>,

    // Utils
    pub _p: PhantomData<CV>,
}

impl<C: ProjectiveCurve, CV: CurveVar<C, ConstraintF<C>>> ConstraintSynthesizer<ConstraintF<C>>
    for ProposalCreationCircuitGeneric<C, CV>
where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF<C>>,
    ) -> ark_relations::r1cs::Result<()> {
        let param_var = <CV as AllocVar<_, _>>::new_input(cs.clone(), || Ok(self.param))?;
        let pk_var = PublicKeyVar::<C, CV>::new_input(cs.clone(), || Ok(self.pk))?;

        let sk_var = SecretKeyVar::new_witness(cs, || Ok(self.sk))?;

        pk_var
            .pk
            .enforce_equal(&param_var.scalar_mul_le(sk_var.0.to_bits_le()?.iter())?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::{
        encryption::{
            elgamal::{ElGamal, SecretKey},
            AsymmetricEncryptionScheme,
        },
        CircuitSpecificSetupSNARK, SNARK,
    };
    use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_std::test_rng;

    use super::ProposalCreationCircuit;

    type MyEnc = ElGamal<EdwardsProjective>;

    #[test]
    #[ignore = "Long compute time ~10.05s"]
    fn create_proposal_verify() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        let parameters = MyEnc::setup(&mut rng)?;
        let (pk, sk) = MyEnc::keygen(&parameters, &mut rng)?;

        let (cpk, cvk) = Groth16::<Bls12_381>::setup(
            ProposalCreationCircuit {
                param: parameters.generator,
                pk,
                sk: SecretKey(sk.0.clone()),
                _p: std::marker::PhantomData,
            },
            &mut rng,
        )?;

        let proof = Groth16::<Bls12_381>::prove(
            &cpk,
            ProposalCreationCircuit {
                param: parameters.generator,
                pk,
                sk,
                _p: std::marker::PhantomData,
            },
            &mut rng,
        )?;

        let is_verified = Groth16::<Bls12_381>::verify(
            &cvk,
            &[parameters.generator.x, parameters.generator.y, pk.x, pk.y],
            &proof,
        )?;

        assert!(is_verified);

        let random_generator = EdwardsAffine::rand(&mut rng);

        let is_verified = Groth16::<Bls12_381>::verify(
            &cvk,
            &[random_generator.x, random_generator.y, pk.x, pk.y],
            &proof,
        )?;

        assert!(!is_verified);

        Ok(())
    }
}
