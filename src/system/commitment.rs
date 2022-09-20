use std::collections::{hash_map::Entry, BTreeMap, HashMap};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
use ark_ed_on_bls12_381::Fq;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::rand::{CryptoRng, Rng};
use arkworks_native_gadgets::{
    merkle_tree::SparseMerkleTree,
    poseidon::{FieldHasher, Poseidon},
};
use arkworks_utils::Curve;

use crate::{
    circuit::{commitment::VotingCommitmentCircuit, registration::CommitmentRegistrationCircuit},
    utils::setup_params,
};

use super::error::SystemError;

pub struct VotingCommitmentSystem<R: Rng + CryptoRng, const N: usize> {
    pub votes: HashMap<Fq, u32>, // nullifier -> vote
    pub rng: R,
    pub hasher: Poseidon<Fq>,
    pub vote_id: u32,
    pub next_whitelist_idx: u32,
    pub next_commitment_idx: u32,
    pub whitelist_tree: SparseMerkleTree<Fq, Poseidon<Fq>, N>,
    pub commitment_tree: SparseMerkleTree<Fq, Poseidon<Fq>, N>,
    pub registration_key: (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>),
    pub vote_key: (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>),
}

impl<R: Rng + CryptoRng, const N: usize> VotingCommitmentSystem<R, N> {
    pub fn setup(mut rng: R, vote_id: u32) -> Result<Self, SystemError> {
        let poseidon = Poseidon::<Fq>::new(setup_params(Curve::Bls381, 5, 5));
        let zero = Fq::zero();
        let commitment_tree = SparseMerkleTree::<_, _, N>::new_sequential(
            &[],
            &poseidon,
            &zero.into_repr().to_bytes_be(),
        )?;
        let whitelist_tree = SparseMerkleTree::<_, _, N>::new_sequential(
            &[],
            &poseidon,
            &zero.into_repr().to_bytes_be(),
        )?;

        let vote_key = Groth16::<Bls12_381>::setup(
            VotingCommitmentCircuit::<N> {
                hasher: poseidon.clone(),
                nullifier_hash: Fq::rand(&mut rng),
                vote_id: Fq::rand(&mut rng),
                commitment_root: Fq::rand(&mut rng),
                whitelist_root: Fq::rand(&mut rng),
                address: Fq::rand(&mut rng),
                randomness: Fq::rand(&mut rng),
                nullifier: Fq::rand(&mut rng),
                commitment_proof: commitment_tree.generate_membership_proof(0),
                whitelist_proof: whitelist_tree.generate_membership_proof(0),
            },
            &mut rng,
        )?;

        let registration_key = Groth16::<Bls12_381>::setup(
            CommitmentRegistrationCircuit {
                hasher: poseidon.clone(),
                address: Fq::rand(&mut rng),
                commitment: Fq::rand(&mut rng),
                randomness: Fq::rand(&mut rng),
                nullifier: Fq::rand(&mut rng),
            },
            &mut rng,
        )?;

        Ok(Self {
            rng,
            hasher: poseidon,
            vote_id,
            next_whitelist_idx: 0,
            next_commitment_idx: 0,
            whitelist_tree,
            commitment_tree,
            registration_key,
            vote_key,
            votes: HashMap::new(),
        })
    }

    pub fn generate_commitment_proof(
        &mut self,
        commitment: Fq,
        address: Fq,
        randomness: Fq,
        nullifier: Fq,
    ) -> Result<Proof<Bls12_381>, SystemError> {
        Ok(Groth16::prove(
            &self.registration_key.0,
            CommitmentRegistrationCircuit {
                commitment,
                address,
                randomness,
                nullifier,
                hasher: self.hasher.clone(),
            },
            &mut self.rng,
        )?)
    }

    pub fn generate_voting_proof(
        &mut self,
        whitelist_index: u32,
        commitment_index: u32,
        nullifier_hash: Fq,
        address: Fq,
        randomness: Fq,
        nullifier: Fq,
    ) -> Result<Proof<Bls12_381>, SystemError> {
        Ok(Groth16::prove(
            &self.vote_key.0,
            VotingCommitmentCircuit::<N> {
                commitment_root: self.commitment_tree.root(),
                whitelist_root: self.whitelist_tree.root(),
                nullifier_hash,
                vote_id: Fq::from(self.vote_id),
                address,
                randomness,
                nullifier,
                commitment_proof: self
                    .commitment_tree
                    .generate_membership_proof(commitment_index as u64),
                whitelist_proof: self
                    .whitelist_tree
                    .generate_membership_proof(whitelist_index as u64),
                hasher: self.hasher.clone(),
            },
            &mut self.rng,
        )?)
    }

    pub fn insert_commitment(
        &mut self,
        commitment: Fq,
        address: Fq,
        proof: &Proof<Bls12_381>,
    ) -> Result<u32, SystemError> {
        Groth16::verify(&self.registration_key.1, &[commitment, address], &proof)?
            .then_some(())
            .ok_or(SystemError::InvalidProof)?;

        let index = self.next_commitment_idx;

        self.commitment_tree
            .insert_batch(&BTreeMap::from_iter([(index, commitment)]), &self.hasher)?;

        self.next_commitment_idx += 1;

        Ok(index)
    }

    pub fn insert_whitelist(&mut self, address: Fq) -> Result<u32, SystemError> {
        let addr_hashed = self.hasher.hash_two(&address, &address)?;

        let index = self.next_whitelist_idx;

        self.whitelist_tree
            .insert_batch(&BTreeMap::from_iter([(index, addr_hashed)]), &self.hasher)?;

        self.next_whitelist_idx += 1;

        Ok(index)
    }

    pub fn vote(
        &mut self,
        vote: u32,
        nullifier_hash: Fq,
        proof: &Proof<Bls12_381>,
    ) -> Result<(), SystemError> {
        Groth16::verify(
            &self.vote_key.1,
            &[
                self.commitment_tree.root(),
                self.whitelist_tree.root(),
                nullifier_hash,
                Fq::from(self.vote_id),
            ],
            &proof,
        )?
        .then_some(())
        .ok_or(SystemError::InvalidProof)?;

        match self.votes.entry(nullifier_hash) {
            Entry::Occupied(_) => {
                Err(SystemError::UsedNullifier)?;
            }
            Entry::Vacant(entry) => {
                entry.insert(vote);
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_ed_on_bls12_381::Fq;
    use ark_ff::{PrimeField, UniformRand};
    use ark_std::test_rng;
    use arkworks_native_gadgets::poseidon::FieldHasher;

    use crate::system::error::SystemError;

    use super::VotingCommitmentSystem;

    #[test]
    #[ignore = "Long compute time ~27s"]
    fn vote() -> Result<(), Box<dyn Error>> {
        let mut system = VotingCommitmentSystem::<_, 10>::setup(test_rng(), 0)?;

        let address = Fq::from_be_bytes_mod_order(b"someassaddr");
        let randomness = Fq::rand(&mut system.rng);
        let nullifier = Fq::rand(&mut system.rng);
        let commitment = system
            .hasher
            .hash_two(&system.hasher.hash_two(&address, &randomness)?, &nullifier)?;
        let nullifier_hash = system
            .hasher
            .hash_two(&nullifier, &Fq::from(system.vote_id))?;

        let regis_proof =
            system.generate_commitment_proof(commitment, address, randomness, nullifier)?;
        let commitment_idx = system.insert_commitment(commitment, address, &regis_proof)?;
        let whitelist_idx = system.insert_whitelist(address)?;

        let vote_proof = system.generate_voting_proof(
            whitelist_idx,
            commitment_idx,
            nullifier_hash,
            address,
            randomness,
            nullifier,
        )?;

        system.vote(1, nullifier_hash, &vote_proof)?;

        let err = system.vote(2, nullifier_hash, &vote_proof).unwrap_err();
        assert_eq!(err, SystemError::UsedNullifier);

        Ok(())
    }
}
