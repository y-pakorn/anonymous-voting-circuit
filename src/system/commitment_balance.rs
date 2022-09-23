use std::collections::{hash_map::Entry, BTreeMap, HashMap};

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::{
    encryption::{
        elgamal::{ElGamal, Parameters, PublicKey, Randomness, SecretKey},
        AsymmetricEncryptionScheme,
    },
    CircuitSpecificSetupSNARK, SNARK,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::rand::{CryptoRng, Rng};
use arkworks_native_gadgets::{
    merkle_tree::SparseMerkleTree,
    poseidon::{FieldHasher, Poseidon},
};
use arkworks_utils::Curve;

use crate::{
    circuit::{
        commitment_balance::VotingCommitmentBalanceCircuit,
        registration::CommitmentRegistrationCircuit,
    },
    lookup_table::LookupTable,
    utils::setup_params,
};

use super::error::SystemError;

pub struct VotingCommitmentBalanceSystem<R: Rng + CryptoRng, const N: usize, const MAX: u64> {
    pub current_result_encoded: (EdwardsAffine, EdwardsAffine),
    pub lookup_table: LookupTable<EdwardsAffine>,
    pub votes: HashMap<Fr, ()>, // nullifier
    pub rng: R,
    pub hasher: Poseidon<Fr>,
    pub vote_id: u32,
    pub next_whitelist_idx: u32,
    pub next_commitment_idx: u32,
    pub whitelist_tree: SparseMerkleTree<Fr, Poseidon<Fr>, N>,
    pub commitment_tree: SparseMerkleTree<Fr, Poseidon<Fr>, N>,
    pub registration_key: (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>),
    pub vote_key: (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>),
    pub elgamal: (
        Parameters<EdwardsProjective>,
        PublicKey<EdwardsProjective>,
        SecretKey<EdwardsProjective>,
    ),
}

impl<R: Rng + CryptoRng, const N: usize, const MAX: u64> VotingCommitmentBalanceSystem<R, N, MAX> {
    pub fn setup(mut rng: R, vote_id: u32) -> Result<Self, SystemError> {
        let poseidon = Poseidon::<Fr>::new(setup_params(Curve::Bls381, 5, 5));
        let zero = Fr::zero();
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
            VotingCommitmentBalanceCircuit::<N> {
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
                elg_param: EdwardsAffine::rand(&mut rng),
                elg_pk: EdwardsAffine::rand(&mut rng),
                before_result: (EdwardsAffine::rand(&mut rng), EdwardsAffine::rand(&mut rng)),
                after_result: (EdwardsAffine::rand(&mut rng), EdwardsAffine::rand(&mut rng)),
                balance: Fr::rand(&mut rng),
                balance_affine: EdwardsAffine::rand(&mut rng),
                elg_randomness: Randomness::rand(&mut rng),
            },
            &mut rng,
        )?;

        let registration_key = Groth16::<Bls12_381>::setup(
            CommitmentRegistrationCircuit {
                hasher: poseidon.clone(),
                address: Fr::rand(&mut rng),
                commitment: Fr::rand(&mut rng),
                randomness: Fr::rand(&mut rng),
                nullifier: Fr::rand(&mut rng),
            },
            &mut rng,
        )?;

        let param = ElGamal::<EdwardsProjective>::setup(&mut rng).unwrap();
        let (pk, sk) = ElGamal::keygen(&param, &mut rng).unwrap();
        let randomness = Randomness::<EdwardsProjective>::rand(&mut rng);
        let zero = ElGamal::encrypt(
            &param,
            &pk,
            &EdwardsAffine::prime_subgroup_generator()
                .mul(Fr::zero())
                .into_affine(),
            &randomness,
        )
        .unwrap();

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
            current_result_encoded: zero,
            elgamal: (param, pk, sk),
            lookup_table: LookupTable::new(0..MAX),
        })
    }

    pub fn generate_commitment_proof(
        &mut self,
        commitment: Fr,
        address: Fr,
        randomness: Fr,
        nullifier: Fr,
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
        address: Fr,
        randomness: Fr,
        nullifier: Fr,
        balance: Fr,
    ) -> Result<(Proof<Bls12_381>, Fr, (EdwardsAffine, EdwardsAffine)), SystemError> {
        let nullifier_hash = self.hasher.hash_two(&nullifier, &Fr::from(self.vote_id))?;
        let elg_randomness = Randomness::<EdwardsProjective>::rand(&mut self.rng);
        let balance_affine = EdwardsAffine::prime_subgroup_generator()
            .mul(balance)
            .into_affine();
        let balance_encrypted = ElGamal::encrypt(
            &self.elgamal.0,
            &self.elgamal.1,
            &balance_affine,
            &elg_randomness,
        )?;
        let after_result = (
            self.current_result_encoded.0 + balance_encrypted.0,
            self.current_result_encoded.1 + balance_encrypted.1,
        );

        Ok((
            Groth16::prove(
                &self.vote_key.0,
                VotingCommitmentBalanceCircuit::<N> {
                    commitment_root: self.commitment_tree.root(),
                    whitelist_root: self.whitelist_tree.root(),
                    nullifier_hash,
                    vote_id: Fr::from(self.vote_id),
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
                    elg_param: self.elgamal.0.generator,
                    elg_pk: self.elgamal.1,
                    before_result: self.current_result_encoded,
                    after_result,
                    balance,
                    balance_affine,
                    elg_randomness,
                },
                &mut self.rng,
            )?,
            nullifier_hash,
            after_result,
        ))
    }

    pub fn insert_commitment(
        &mut self,
        commitment: Fr,
        address: Fr,
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

    pub fn insert_whitelist(&mut self, address: Fr, balance: Fr) -> Result<u32, SystemError> {
        let leaf = self.hasher.hash_two(&address, &balance)?;

        let index = self.next_whitelist_idx;

        self.whitelist_tree
            .insert_batch(&BTreeMap::from_iter([(index, leaf)]), &self.hasher)?;

        self.next_whitelist_idx += 1;

        Ok(index)
    }

    pub fn vote(
        &mut self,
        nullifier_hash: Fr,
        after_result: (EdwardsAffine, EdwardsAffine),
        proof: &Proof<Bls12_381>,
    ) -> Result<(), SystemError> {
        Groth16::verify(
            &self.vote_key.1,
            &[
                self.commitment_tree.root(),
                self.whitelist_tree.root(),
                nullifier_hash,
                Fr::from(self.vote_id),
                self.elgamal.0.generator.x,
                self.elgamal.0.generator.y,
                self.elgamal.1.x,
                self.elgamal.1.y,
                self.current_result_encoded.0.x,
                self.current_result_encoded.0.y,
                self.current_result_encoded.1.x,
                self.current_result_encoded.1.y,
                after_result.0.x,
                after_result.0.y,
                after_result.1.x,
                after_result.1.y,
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
                entry.insert(());
            }
        };

        self.current_result_encoded = after_result;

        Ok(())
    }

    pub fn decode_current_result(&self) -> Result<u64, SystemError> {
        let decoded = ElGamal::decrypt(
            &self.elgamal.0,
            &self.elgamal.2,
            &self.current_result_encoded,
        )?;
        self.lookup_table
            .get(&decoded)
            .ok_or(SystemError::ExceedMaxLookup)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use ark_std::test_rng;
    use arkworks_native_gadgets::poseidon::FieldHasher;

    use crate::system::error::SystemError;

    use super::VotingCommitmentBalanceSystem;

    #[test]
    #[ignore = "Long compute time ~44.67s"]
    fn vote() -> Result<(), Box<dyn Error>> {
        let mut system = VotingCommitmentBalanceSystem::<_, 10, 1000>::setup(test_rng(), 0)?;

        let address = Fr::from_be_bytes_mod_order(b"someassaddr");
        let balance = Fr::from(100);
        let randomness = Fr::rand(&mut system.rng);
        let nullifier = Fr::rand(&mut system.rng);
        let commitment = system
            .hasher
            .hash_two(&system.hasher.hash_two(&address, &randomness)?, &nullifier)?;

        let regis_proof =
            system.generate_commitment_proof(commitment, address, randomness, nullifier)?;
        let commitment_idx = system.insert_commitment(commitment, address, &regis_proof)?;
        let whitelist_idx = system.insert_whitelist(address, balance)?;

        let (vote_proof, nullifier_hash, after_result) = system.generate_voting_proof(
            whitelist_idx,
            commitment_idx,
            address,
            randomness,
            nullifier,
            balance,
        )?;

        assert_eq!(system.decode_current_result()?, 0);

        system.vote(nullifier_hash, after_result, &vote_proof)?;

        let err = system
            .vote(nullifier_hash, after_result, &vote_proof)
            .unwrap_err();
        assert_eq!(err, SystemError::InvalidProof);
        assert_eq!(system.decode_current_result()?, 100);

        Ok(())
    }
}
