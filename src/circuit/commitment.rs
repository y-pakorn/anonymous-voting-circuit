use ark_bls12_381::Fr;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, EqGadget},
};
use ark_relations::r1cs::ConstraintSynthesizer;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_r1cs_gadgets::{
    merkle_tree::PathVar,
    poseidon::{FieldHasherGadget, PoseidonGadget},
};

pub struct VotingCommitmentCircuit<const N: usize> {
    // Public
    pub commitment_root: Fr,
    pub whitelist_root: Fr,
    pub nullifier_hash: Fr,
    pub vote_id: Fr,

    // Secret
    // commitment = H(H(addr, r), nullifier)
    pub address: Fr,
    pub randomness: Fr,
    pub nullifier: Fr,
    pub commitment_proof: Path<Fr, <PoseidonGadget<Fr> as FieldHasherGadget<Fr>>::Native, N>,
    pub whitelist_proof: Path<Fr, <PoseidonGadget<Fr> as FieldHasherGadget<Fr>>::Native, N>,

    // Utils
    pub hasher: <PoseidonGadget<Fr> as FieldHasherGadget<Fr>>::Native,
}

impl<const N: usize> ConstraintSynthesizer<Fr> for VotingCommitmentCircuit<N> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: PoseidonGadget<Fr> =
            FieldHasherGadget::<Fr>::from_native(&mut cs.clone(), self.hasher)?;

        // Public
        let commitment_root_var = FpVar::new_input(cs.clone(), || Ok(self.commitment_root))?;
        let whitelist_root_var = FpVar::new_input(cs.clone(), || Ok(self.whitelist_root))?;
        let nullifier_hash_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier_hash))?;
        let vote_id_var = FpVar::new_input(cs.clone(), || Ok(self.vote_id))?;

        // Secret
        let address_var = FpVar::new_witness(cs.clone(), || Ok(self.address))?;
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(self.randomness))?;
        let nullifier_var = FpVar::new_witness(cs.clone(), || Ok(self.nullifier))?;
        let commitment_proof_var =
            PathVar::<Fr, PoseidonGadget<Fr>, N>::new_witness(cs.clone(), || {
                Ok(self.commitment_proof)
            })?;
        let whitelist_proof_var =
            PathVar::<Fr, PoseidonGadget<Fr>, N>::new_witness(cs.clone(), || {
                Ok(self.whitelist_proof)
            })?;

        let secret = hasher_var.hash_two(&address_var, &randomness_var)?;
        let commitment = hasher_var.hash_two(&secret, &nullifier_var)?;
        let nullifier_hashed = hasher_var.hash_two(&nullifier_var, &vote_id_var)?;
        let address_hashed = hasher_var.hash_two(&address_var, &address_var)?;

        let is_correct_whitelist = whitelist_proof_var.check_membership(
            &whitelist_root_var,
            &address_hashed,
            &hasher_var,
        )?;
        let is_correct_commitment = commitment_proof_var.check_membership(
            &commitment_root_var,
            &commitment,
            &hasher_var,
        )?;

        nullifier_hash_var.enforce_equal(&nullifier_hashed)?;
        is_correct_whitelist.enforce_equal(&Boolean::TRUE)?;
        is_correct_commitment.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error, iter::FromIterator};

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
    use ark_groth16::Groth16;
    use ark_std::test_rng;
    use arkworks_native_gadgets::{
        merkle_tree::SparseMerkleTree,
        poseidon::{FieldHasher, Poseidon},
    };
    use arkworks_utils::Curve;

    use crate::utils::setup_params;

    use super::VotingCommitmentCircuit;

    #[test]
    #[ignore = "Long compute time ~16.2s"]
    fn voting_commitment_verify_simple() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let poseidon = Poseidon::<Fr>::new(setup_params(Curve::Bls381, 5, 5));
        let zero = Fr::zero();

        let mut commitment_tree = SparseMerkleTree::<_, _, 5>::new_sequential(
            &[],
            &poseidon,
            &zero.into_repr().to_bytes_be(),
        )?;
        let mut whitelist_tree = SparseMerkleTree::<_, _, 5>::new_sequential(
            &[],
            &poseidon,
            &zero.into_repr().to_bytes_be(),
        )?;

        let (pk, vk) = Groth16::<Bls12_381>::setup(
            VotingCommitmentCircuit::<5> {
                hasher: poseidon.clone(),
                nullifier_hash: Fr::rand(&mut rng),
                vote_id: Fr::rand(&mut rng),
                commitment_root: Fr::rand(&mut rng),
                whitelist_root: Fr::rand(&mut rng),
                address: Fr::rand(&mut rng),
                randomness: Fr::rand(&mut rng),
                nullifier: Fr::rand(&mut rng),
                commitment_proof: commitment_tree.generate_membership_proof(0),
                whitelist_proof: whitelist_tree.generate_membership_proof(0),
            },
            &mut rng,
        )?;

        let addr = Fr::from_be_bytes_mod_order(b"someassaddr");
        let randomness = Fr::rand(&mut rng);
        let nullifier = Fr::rand(&mut rng);
        let vote_id = Fr::from(0);

        let nullifier_hash = poseidon.hash_two(&nullifier, &vote_id)?;
        let commitment = poseidon.hash_two(&poseidon.hash_two(&addr, &randomness)?, &nullifier)?;
        let addr_hashed = poseidon.hash_two(&addr, &addr)?;

        whitelist_tree.insert_batch(&BTreeMap::from_iter([(0, addr_hashed)]), &poseidon)?;
        commitment_tree.insert_batch(&BTreeMap::from_iter([(0, commitment)]), &poseidon)?;

        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            VotingCommitmentCircuit::<5> {
                hasher: poseidon.clone(),
                nullifier_hash,
                vote_id,
                commitment_root: commitment_tree.root(),
                whitelist_root: whitelist_tree.root(),
                address: addr,
                randomness,
                nullifier,
                commitment_proof: commitment_tree.generate_membership_proof(0),
                whitelist_proof: whitelist_tree.generate_membership_proof(0),
            },
            &mut rng,
        )?;

        let verified = Groth16::verify(
            &vk,
            &[
                commitment_tree.root(),
                whitelist_tree.root(),
                nullifier_hash,
                vote_id,
            ],
            &proof,
        )?;

        assert!(verified);

        Ok(())
    }
}
