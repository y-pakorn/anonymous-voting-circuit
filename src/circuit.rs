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

pub struct VotingCommitmentCircuit<const N: usize> {
    // Public
    pub commitment_root: Fq,
    pub whitelist_root: Fq,
    pub nullifier_hash: Fq,
    pub vote_id: Fq,

    // Secret
    // commitment = H(H(addr, r), nullifier)
    pub address: Fq,
    pub randomness: Fq,
    pub nullifier: Fq,
    pub commitment_proof: Path<Fq, <PoseidonGadget<Fq> as FieldHasherGadget<Fq>>::Native, N>,
    pub whitelist_proof: Path<Fq, <PoseidonGadget<Fq> as FieldHasherGadget<Fq>>::Native, N>,

    // Utils
    pub hasher: <PoseidonGadget<Fq> as FieldHasherGadget<Fq>>::Native,
}

impl<const N: usize> ConstraintSynthesizer<Fq> for VotingCommitmentCircuit<N> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fq>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: PoseidonGadget<Fq> =
            FieldHasherGadget::<Fq>::from_native(&mut cs.clone(), self.hasher)?;

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
            PathVar::<Fq, PoseidonGadget<Fq>, N>::new_witness(cs.clone(), || {
                Ok(self.commitment_proof)
            })?;
        let whitelist_proof_var =
            PathVar::<Fq, PoseidonGadget<Fq>, N>::new_witness(cs.clone(), || {
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

pub struct CommitmentRegistrationCircuit {
    // Public
    pub commitment: Fq,
    pub address: Fq,

    // Secret
    pub randomness: Fq,
    pub nullifier: Fq,

    // Utils
    pub hasher: <PoseidonGadget<Fq> as FieldHasherGadget<Fq>>::Native,
}

impl ConstraintSynthesizer<Fq> for CommitmentRegistrationCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fq>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: PoseidonGadget<Fq> =
            FieldHasherGadget::<Fq>::from_native(&mut cs.clone(), self.hasher)?;

        // Public
        let commitment_var = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        let address_var = FpVar::new_input(cs.clone(), || Ok(self.address))?;

        // Secret
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(self.randomness))?;
        let nullifier_var = FpVar::new_witness(cs.clone(), || Ok(self.nullifier))?;

        let secret = hasher_var.hash_two(&address_var, &randomness_var)?;
        let commitment = hasher_var.hash_two(&secret, &nullifier_var)?;

        commitment_var.enforce_equal(&commitment)?;

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
        poseidon::{sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters},
    };
    use arkworks_utils::{
        bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
    };

    use crate::{
        circuit::CommitmentRegistrationCircuit,
        signature::{schnorr::Schnorr, SignatureScheme},
    };

    use super::{VotingCommitmentCircuit, VotingSignatureCircuit};

    pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
        let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

        let mds_f = bytes_matrix_to_f(&pos_data.mds);
        let rounds_f = bytes_vec_to_f(&pos_data.rounds);

        let pos = PoseidonParameters {
            mds_matrix: mds_f,
            round_keys: rounds_f,
            full_rounds: pos_data.full_rounds,
            partial_rounds: pos_data.partial_rounds,
            sbox: PoseidonSbox(pos_data.exp),
            width: pos_data.width,
        };

        pos
    }

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

    #[test]
    #[ignore = "Long compute time ~16.2s"]
    fn voting_commitment_verify_simple() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let poseidon = Poseidon::<Fq>::new(setup_params(Curve::Bls381, 5, 5));
        let zero = Fq::zero();

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

        let addr = Fq::from_be_bytes_mod_order(b"someassaddr");
        let randomness = Fq::rand(&mut rng);
        let nullifier = Fq::rand(&mut rng);
        let vote_id = Fq::from(0);

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

    #[test]
    #[ignore = "Long compute time ~3.14s"]
    fn registration_verify_simple() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let poseidon = Poseidon::<Fq>::new(setup_params(Curve::Bls381, 5, 5));

        let (pk, vk) = Groth16::<Bls12_381>::setup(
            CommitmentRegistrationCircuit {
                hasher: poseidon.clone(),
                address: Fq::rand(&mut rng),
                commitment: Fq::rand(&mut rng),
                randomness: Fq::rand(&mut rng),
                nullifier: Fq::rand(&mut rng),
            },
            &mut rng,
        )?;

        let addr = Fq::from_be_bytes_mod_order(b"someassaddr");
        let randomness = Fq::rand(&mut rng);
        let nullifier = Fq::rand(&mut rng);

        let commitment = poseidon.hash_two(&poseidon.hash_two(&addr, &randomness)?, &nullifier)?;

        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            CommitmentRegistrationCircuit {
                hasher: poseidon.clone(),
                address: addr,
                commitment,
                randomness,
                nullifier,
            },
            &mut rng,
        )?;

        let verified = Groth16::verify(&vk, &[commitment, addr], &proof)?;

        assert!(verified);

        Ok(())
    }
}
