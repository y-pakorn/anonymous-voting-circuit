use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
use ark_ff::{PrimeField, ToBytes};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, EqGadget},
    ToBytesGadget,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_r1cs_gadgets::{
    merkle_tree::PathVar,
    poseidon::{FieldHasherGadget, PoseidonGadget},
};

use crate::signature::{
    schnorr::{
        constraints::{ParametersVar, PublicKeyVar, SchnorrSignatureVerifyGadget, SignatureVar},
        Schnorr,
    },
    SigVerifyGadget, SignatureScheme,
};

pub struct VotingSignatureCircuit<const N: usize> {
    // Public
    pub merkle_root: Fq,
    pub nullifier_hash: Fq,
    pub vote_id: Fq,
    pub param: <Schnorr<JubJub> as SignatureScheme>::Parameters,

    // Secret
    pub signature: <Schnorr<JubJub> as SignatureScheme>::Signature,
    pub pk: <Schnorr<JubJub> as SignatureScheme>::PublicKey,
    pub merkle_proof: Path<Fq, <PoseidonGadget<Fq> as FieldHasherGadget<Fq>>::Native, N>,

    // Utils
    pub hasher: <PoseidonGadget<Fq> as FieldHasherGadget<Fq>>::Native,
}

impl<const N: usize> ConstraintSynthesizer<Fq> for VotingSignatureCircuit<N> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fq>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: PoseidonGadget<Fq> =
            FieldHasherGadget::<Fq>::from_native(&mut cs.clone(), self.hasher)?;

        // Public
        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(self.merkle_root))?;
        let nullifier_hash_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier_hash))?;
        let vote_id_var = FpVar::new_input(cs.clone(), || Ok(self.vote_id))?;
        let schnorr_param_var =
            ParametersVar::<JubJub, EdwardsVar>::new_input(cs.clone(), || Ok(self.param))?;

        // Secret
        let signature_var =
            SignatureVar::<JubJub, EdwardsVar>::new_witness(cs.clone(), || Ok(self.signature))?;
        let pk_var = PublicKeyVar::<JubJub, EdwardsVar>::new_witness(cs.clone(), || Ok(self.pk))?;

        let mut pk_bytes = vec![];
        self.pk.write(&mut pk_bytes).unwrap();
        let pk_fpvar =
            FpVar::new_witness(cs.clone(), || Ok(Fq::from_be_bytes_mod_order(&pk_bytes)))?;
        let merkle_proof_var = PathVar::<Fq, PoseidonGadget<Fq>, N>::new_witness(
            cs.clone(),
            || Ok(self.merkle_proof),
        )?;

        let is_signature_verified = SchnorrSignatureVerifyGadget::<JubJub, EdwardsVar>::verify(
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

    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fq};
    use ark_ff::{BigInteger, PrimeField, ToBytes, ToConstraintField, UniformRand, Zero};
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
    #[ignore = "Long compute time ~110s"]
    fn voting_signature_verify_simple() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let poseidon = Poseidon::<Fq>::new(setup_params(Curve::Bls381, 5, 5));
        let zero = Fq::zero();
        let mut tree = SparseMerkleTree::<_, _, 5>::new_sequential(
            &[],
            &poseidon,
            &zero.into_repr().to_bytes_be(),
        )?;
        let vote_id = Fq::from(0);

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
                nullifier_hash: Fq::rand(&mut rng),
                vote_id,
                param: param.clone(),
                signature: signature.clone(),
                pk: public_key,
                merkle_proof: tree.generate_membership_proof(0),
                hasher: poseidon.clone(),
            },
            &mut rng,
        )?;

        let mut pk_bytes = vec![];
        public_key.write(&mut pk_bytes)?;
        let pk_fp = Fq::from_be_bytes_mod_order(&pk_bytes);
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
            },
            &mut rng,
        )?;

        let verified = Groth16::verify(
            &vk,
            &[
                tree.root(),
                nullifier,
                vote_id,
                param.to_field_elements().unwrap()[0],
                param.to_field_elements().unwrap()[1],
            ],
            &proof,
        )?;

        assert!(verified);

        Ok(())
    }
}
