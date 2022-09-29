use std::marker::PhantomData;

use ark_bls12_381::Fr;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_r1cs_gadgets::{
    merkle_tree::PathVar,
    poseidon::{FieldHasherGadget, PoseidonGadget},
};

use crate::{
    signature::{
        schnorr::{
            constraints::{
                ParametersVar, PublicKeyVar, SchnorrSignatureVerifyGadget, SignatureVar,
            },
            Schnorr,
        },
        SigVerifyGadget, SignatureScheme,
    },
    utils::ConstraintF,
};

pub type VotingSignatureCircuit<const N: usize> =
    VotingSignatureCircuitGeneric<EdwardsProjective, PoseidonGadget<Fr>, EdwardsVar, N>;

pub struct VotingSignatureCircuitGeneric<
    C: ProjectiveCurve,
    HG: FieldHasherGadget<ConstraintF<C>>,
    CV: CurveVar<C, ConstraintF<C>> + ToConstraintFieldGadget<ConstraintF<C>>,
    const N: usize,
> where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Public
    pub merkle_root: ConstraintF<C>,
    pub nullifier_hash: ConstraintF<C>,
    pub vote_id: ConstraintF<C>,
    pub param: <Schnorr<C> as SignatureScheme>::Parameters,

    // Secret
    pub signature: <Schnorr<C> as SignatureScheme>::Signature,
    pub pk: <Schnorr<C> as SignatureScheme>::PublicKey,
    pub merkle_proof: Path<ConstraintF<C>, HG::Native, N>,

    // Utils
    pub hasher: HG::Native,
    pub _p: PhantomData<CV>,
}

impl<
        C: ProjectiveCurve,
        HG: FieldHasherGadget<ConstraintF<C>>,
        CV: CurveVar<C, ConstraintF<C>> + ToConstraintFieldGadget<ConstraintF<C>>,
        const N: usize,
    > ConstraintSynthesizer<ConstraintF<C>> for VotingSignatureCircuitGeneric<C, HG, CV, N>
where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF<C>>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: HG = FieldHasherGadget::from_native(&mut cs.clone(), self.hasher)?;

        // Public
        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(self.merkle_root))?;
        let nullifier_hash_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier_hash))?;
        let vote_id_var = FpVar::new_input(cs.clone(), || Ok(self.vote_id))?;
        let schnorr_param_var = ParametersVar::<C, CV>::new_input(cs.clone(), || Ok(self.param))?;

        // Secret
        let signature_var = SignatureVar::<C, CV>::new_witness(cs.clone(), || Ok(self.signature))?;
        let pk_var = PublicKeyVar::<C, CV>::new_witness(cs.clone(), || Ok(self.pk))?;
        let pk_cfs = pk_var.pub_key.to_constraint_field()?;

        let pk_fpvar = hasher_var.hash_two(&pk_cfs[0], &pk_cfs[1])?;
        let merkle_proof_var =
            PathVar::<_, _, N>::new_witness(cs.clone(), || Ok(self.merkle_proof))?;

        let is_signature_verified = SchnorrSignatureVerifyGadget::<C, CV>::verify(
            &schnorr_param_var,
            &pk_var,
            &vote_id_var.to_bytes()?,
            &signature_var,
        )?;

        let nullifier_hashed = hasher_var.hash_two(&pk_fpvar, &vote_id_var)?;

        let leaf = hasher_var.hash_two(&pk_fpvar, &pk_fpvar)?;
        let is_correct_proof =
            merkle_proof_var.check_membership(&merkle_root_var, &leaf, &hasher_var)?;

        is_signature_verified.enforce_equal(&Boolean::TRUE)?;
        is_correct_proof.enforce_equal(&Boolean::TRUE)?;
        nullifier_hashed.enforce_equal(&nullifier_hash_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error, iter::FromIterator};

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
    use ark_groth16::Groth16;
    use ark_std::test_rng;
    use arkworks_native_gadgets::{
        merkle_tree::SparseMerkleTree,
        poseidon::{FieldHasher, Poseidon},
    };
    use arkworks_utils::Curve;

    use crate::{
        signature::{schnorr::Schnorr, SignatureScheme},
        utils::setup_params,
    };

    use super::VotingSignatureCircuit;

    #[test]
    #[ignore = "Long compute time ~119s"]
    fn voting_signature_verify_simple() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let poseidon = Poseidon::<Fr>::new(setup_params(Curve::Bls381, 5, 5));
        let zero = Fr::zero();
        let mut tree = SparseMerkleTree::<_, _, 5>::new_sequential(
            &[],
            &poseidon,
            &zero.into_repr().to_bytes_be(),
        )?;
        let vote_id = Fr::from(0);

        let param = Schnorr::<JubJub>::setup(&mut rng)?;
        let (public_key, secret_key) = Schnorr::<JubJub>::keygen(&param, &mut rng)?;
        let signature = Schnorr::<JubJub>::sign(
            &param,
            &secret_key,
            &vote_id.into_repr().to_bytes_be(),
            &mut rng,
        )?;

        let (pk, vk) = Groth16::<Bls12_381>::setup(
            VotingSignatureCircuit::<5> {
                merkle_root: tree.root(),
                nullifier_hash: Fr::rand(&mut rng),
                vote_id,
                param: param.clone(),
                signature: signature.clone(),
                pk: public_key,
                merkle_proof: tree.generate_membership_proof(0),
                hasher: poseidon.clone(),
                _p: std::marker::PhantomData,
            },
            &mut rng,
        )?;

        let pk_fp = poseidon.hash_two(&public_key.x, &public_key.y)?;
        let nullifier = poseidon.hash_two(&pk_fp, &vote_id)?;
        let leaf = poseidon.hash_two(&pk_fp, &pk_fp)?;

        tree.insert_batch(&BTreeMap::from_iter([(0, leaf)]), &poseidon)?;

        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            VotingSignatureCircuit::<5> {
                merkle_root: tree.root(),
                nullifier_hash: nullifier,
                vote_id,
                param: param.clone(),
                signature,
                pk: public_key,
                merkle_proof: tree.generate_membership_proof(0),
                hasher: poseidon.clone(),
                _p: std::marker::PhantomData,
            },
            &mut rng,
        )?;

        let verified = Groth16::verify(
            &vk,
            &[
                tree.root(),
                nullifier,
                vote_id,
                param.generator.x,
                param.generator.y,
            ],
            &proof,
        )?;

        assert!(verified);

        Ok(())
    }
}
