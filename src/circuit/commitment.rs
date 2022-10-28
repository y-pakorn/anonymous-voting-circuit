use ark_bls12_381::Fr;
use ark_ff::PrimeField;
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

pub type VotingCommitmentCircuit<const N: usize> =
    VotingCommitmentCircuitGeneric<Fr, PoseidonGadget<Fr>, N>;
pub type VotingCommitmentCircuitNoWhitelist<const N: usize> =
    VotingCommitmentCircuitNoWhitelistGeneric<Fr, PoseidonGadget<Fr>, N>;

pub struct VotingCommitmentCircuitGeneric<F: PrimeField, HG: FieldHasherGadget<F>, const N: usize> {
    // Public
    pub commitment_root: F,
    pub whitelist_root: F,
    pub nullifier_hash: F,
    pub vote_id: F,

    // Secret
    // commitment = H(H(addr, r), nullifier)
    pub address: F,
    pub randomness: F,
    pub nullifier: F,
    pub commitment_proof: Path<F, HG::Native, N>,
    pub whitelist_proof: Path<F, HG::Native, N>,

    // Utils
    pub hasher: HG::Native,
}

impl<F: PrimeField, HG: FieldHasherGadget<F>, const N: usize> ConstraintSynthesizer<F>
    for VotingCommitmentCircuitGeneric<F, HG, N>
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: HG = FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher)?;
        let zero = FpVar::new_constant(cs.clone(), F::zero())?;

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
            PathVar::<F, HG, N>::new_witness(cs.clone(), || Ok(self.commitment_proof))?;
        let whitelist_proof_var =
            PathVar::<F, HG, N>::new_witness(cs, || Ok(self.whitelist_proof))?;

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
        is_correct_commitment.enforce_equal(&Boolean::TRUE)?;

        // Conditionally enfore whitelist path based on whitelist root
        is_correct_whitelist
            .conditional_enforce_equal(&Boolean::TRUE, &whitelist_root_var.is_eq(&zero)?.not())?;

        Ok(())
    }
}

pub struct VotingCommitmentCircuitNoWhitelistGeneric<
    F: PrimeField,
    HG: FieldHasherGadget<F>,
    const N: usize,
> {
    // Public
    pub commitment_root: F,
    pub nullifier_hash: F,
    pub vote_id: F,

    // Secret
    // commitment = H(H(addr, r), nullifier)
    pub address: F,
    pub randomness: F,
    pub nullifier: F,
    pub commitment_proof: Path<F, HG::Native, N>,

    // Utils
    pub hasher: HG::Native,
}

impl<F: PrimeField, HG: FieldHasherGadget<F>, const N: usize> ConstraintSynthesizer<F>
    for VotingCommitmentCircuitNoWhitelistGeneric<F, HG, N>
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: HG = FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher)?;

        // Public
        let commitment_root_var = FpVar::new_input(cs.clone(), || Ok(self.commitment_root))?;
        let nullifier_hash_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier_hash))?;
        let vote_id_var = FpVar::new_input(cs.clone(), || Ok(self.vote_id))?;

        // Secret
        let address_var = FpVar::new_witness(cs.clone(), || Ok(self.address))?;
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(self.randomness))?;
        let nullifier_var = FpVar::new_witness(cs.clone(), || Ok(self.nullifier))?;
        let commitment_proof_var =
            PathVar::<F, HG, N>::new_witness(cs.clone(), || Ok(self.commitment_proof))?;

        let secret = hasher_var.hash_two(&address_var, &randomness_var)?;
        let commitment = hasher_var.hash_two(&secret, &nullifier_var)?;
        let nullifier_hashed = hasher_var.hash_two(&nullifier_var, &vote_id_var)?;

        let is_correct_commitment = commitment_proof_var.check_membership(
            &commitment_root_var,
            &commitment,
            &hasher_var,
        )?;

        nullifier_hash_var.enforce_equal(&nullifier_hashed)?;
        is_correct_commitment.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error, iter::FromIterator};

    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::PairingEngine;
    use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
    use ark_groth16::Groth16;
    use ark_std::{
        rand::{CryptoRng, Rng},
        test_rng,
    };
    use arkworks_native_gadgets::{
        merkle_tree::SparseMerkleTree,
        poseidon::{FieldHasher, Poseidon},
    };
    use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};
    use arkworks_utils::Curve;

    use crate::{circuit::commitment::VotingCommitmentCircuitGeneric, utils::setup_params};

    fn verify_generic<P: PairingEngine, HG: FieldHasherGadget<P::Fr>, R: Rng + CryptoRng>(
        mut rng: R,
        hasher: HG::Native,
    ) -> Result<(), Box<dyn Error>> {
        let zero = P::Fr::zero();

        let mut commitment_tree = SparseMerkleTree::<P::Fr, HG::Native, 5>::new_sequential(
            &[],
            &hasher,
            &zero.into_repr().to_bytes_be(),
        )?;
        let mut whitelist_tree = SparseMerkleTree::<P::Fr, HG::Native, 5>::new_sequential(
            &[],
            &hasher,
            &zero.into_repr().to_bytes_be(),
        )?;

        let (pk, vk) = Groth16::<P>::setup(
            VotingCommitmentCircuitGeneric::<P::Fr, HG, 5> {
                hasher: hasher.clone(),
                nullifier_hash: P::Fr::rand(&mut rng),
                vote_id: P::Fr::rand(&mut rng),
                commitment_root: P::Fr::rand(&mut rng),
                whitelist_root: P::Fr::rand(&mut rng),
                address: P::Fr::rand(&mut rng),
                randomness: P::Fr::rand(&mut rng),
                nullifier: P::Fr::rand(&mut rng),
                commitment_proof: commitment_tree.generate_membership_proof(0),
                whitelist_proof: whitelist_tree.generate_membership_proof(0),
            },
            &mut rng,
        )?;

        let addr = P::Fr::from_be_bytes_mod_order(b"someassaddr");
        let randomness = P::Fr::rand(&mut rng);
        let nullifier = P::Fr::rand(&mut rng);
        let vote_id = P::Fr::zero();

        let nullifier_hash = hasher.hash_two(&nullifier, &vote_id)?;
        let commitment = hasher.hash_two(&hasher.hash_two(&addr, &randomness)?, &nullifier)?;
        let addr_hashed = hasher.hash_two(&addr, &addr)?;

        whitelist_tree.insert_batch(&BTreeMap::from_iter([(0, addr_hashed)]), &hasher)?;
        commitment_tree.insert_batch(&BTreeMap::from_iter([(0, commitment)]), &hasher)?;

        let proof = Groth16::<P>::prove(
            &pk,
            VotingCommitmentCircuitGeneric::<P::Fr, HG, 5> {
                hasher: hasher.clone(),
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

    #[test]
    #[ignore = "Long compute time ~16.17s"]
    fn verify_bls12_381() -> Result<(), Box<dyn Error>> {
        verify_generic::<Bls12_381, PoseidonGadget<_>, _>(
            test_rng(),
            Poseidon::new(setup_params(Curve::Bls381, 5, 5)),
        )
    }

    #[test]
    #[ignore = "Long compute time ~10.638s"]
    fn verify_bn254() -> Result<(), Box<dyn Error>> {
        verify_generic::<Bn254, PoseidonGadget<_>, _>(
            test_rng(),
            Poseidon::new(setup_params(Curve::Bn254, 5, 5)),
        )
    }
}
