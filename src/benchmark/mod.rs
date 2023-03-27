mod pairings;
mod poseidon_exp;
mod poseidon_width;

use std::{collections::BTreeMap, error::Error};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_groth16::Groth16;
use ark_std::{end_timer, start_timer};
use arkworks_native_gadgets::{
    merkle_tree::SparseMerkleTree,
    poseidon::{FieldHasher, Poseidon},
};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use rand::{thread_rng, CryptoRng, Rng};

use crate::{
    circuit::{
        commitment::VotingCommitmentCircuitNoWhitelistGeneric,
        registration::CommitmentRegistrationCircuitGeneric,
    },
    utils::setup_params,
};

#[test]
fn large_bench() -> Result<(), Box<dyn Error>> {
    let hasher = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 3));
    let rng = &mut thread_rng();
    let zero = Fr::zero();
    const HEIGHT: usize = 60;
    let mut commitment_tree = SparseMerkleTree::<Fr, Poseidon<Fr>, HEIGHT>::new_sequential(
        &[],
        &hasher,
        &zero.into_repr().to_bytes_be(),
    )?;

    let (pk, _vk) = Groth16::<Bn254>::setup(
        VotingCommitmentCircuitNoWhitelistGeneric::<Fr, PoseidonGadget<Fr>, HEIGHT> {
            hasher: hasher.clone(),
            nullifier_hash: Fr::rand(rng),
            vote_id: Fr::rand(rng),
            commitment_root: Fr::rand(rng),
            address: Fr::rand(rng),
            randomness: Fr::rand(rng),
            nullifier: Fr::rand(rng),
            commitment_proof: commitment_tree.generate_membership_proof(0),
        },
        rng,
    )?;

    let addr = Fr::from_be_bytes_mod_order(b"someassaddr");
    let randomness = Fr::rand(rng);
    let nullifier = Fr::rand(rng);
    let vote_id = Fr::zero();
    let commitment = hasher.hash_two(&hasher.hash_two(&addr, &randomness)?, &nullifier)?;
    let nullifier_hash = hasher.hash_two(&nullifier, &vote_id)?;

    commitment_tree.insert_batch(&BTreeMap::from_iter(vec![(0, commitment)]), &hasher)?;

    let _proof = Groth16::<Bn254>::prove(
        &pk,
        VotingCommitmentCircuitNoWhitelistGeneric::<Fr, PoseidonGadget<Fr>, HEIGHT> {
            hasher: hasher.clone(),
            nullifier_hash,
            vote_id,
            commitment_root: commitment_tree.root(),
            address: addr,
            randomness,
            nullifier,
            commitment_proof: commitment_tree.generate_membership_proof(0),
        },
        rng,
    )?;

    Ok(())
}

fn run_registration_circuit<E: PairingEngine, R: Rng + CryptoRng>(
    hasher: Poseidon<E::Fr>,
    rng: &mut R,
    _label: &str,
) -> Result<(), Box<dyn Error>> {
    let (pk, vk) = Groth16::<E>::setup(
        CommitmentRegistrationCircuitGeneric::<E::Fr, PoseidonGadget<E::Fr>> {
            hasher: hasher.clone(),
            address: E::Fr::rand(rng),
            commitment: E::Fr::rand(rng),
            randomness: E::Fr::rand(rng),
            nullifier: E::Fr::rand(rng),
        },
        rng,
    )?;

    let addr = E::Fr::from_be_bytes_mod_order(b"someassaddr");
    let randomness = E::Fr::rand(rng);
    let nullifier = E::Fr::rand(rng);

    let timer = start_timer!(|| "Computing Commitment");
    let commitment = hasher.hash_two(&hasher.hash_two(&addr, &randomness)?, &nullifier)?;
    end_timer!(timer);

    let proof = Groth16::<E>::prove(
        &pk,
        CommitmentRegistrationCircuitGeneric::<E::Fr, PoseidonGadget<E::Fr>> {
            hasher: hasher.clone(),
            address: addr,
            commitment,
            randomness,
            nullifier,
        },
        rng,
    )?;

    let verified = Groth16::verify(&vk, &[commitment, addr], &proof)?;

    assert!(verified);

    Ok(())
}

fn run_commitment_circuit<E: PairingEngine, R: Rng + CryptoRng>(
    hasher: Poseidon<E::Fr>,
    rng: &mut R,
    current_participant: usize,
    _label: &str,
) -> Result<(), Box<dyn Error>> {
    assert!(
        current_participant > 0,
        "Current participant cannot be zero"
    );

    let zero = E::Fr::zero();
    let mut commitment_tree = SparseMerkleTree::<E::Fr, Poseidon<E::Fr>, 12>::new_sequential(
        &[],
        &hasher,
        &zero.into_repr().to_bytes_be(),
    )?;

    let (pk, vk) = Groth16::<E>::setup(
        VotingCommitmentCircuitNoWhitelistGeneric::<E::Fr, PoseidonGadget<E::Fr>, 12> {
            hasher: hasher.clone(),
            nullifier_hash: E::Fr::rand(rng),
            vote_id: E::Fr::rand(rng),
            commitment_root: E::Fr::rand(rng),
            address: E::Fr::rand(rng),
            randomness: E::Fr::rand(rng),
            nullifier: E::Fr::rand(rng),
            commitment_proof: commitment_tree.generate_membership_proof(0),
        },
        rng,
    )?;

    let addr = E::Fr::from_be_bytes_mod_order(b"someassaddr");
    let randomness = E::Fr::rand(rng);
    let nullifier = E::Fr::rand(rng);
    let vote_id = E::Fr::zero();

    let timer = start_timer!(|| "Computing Commitment");
    let commitment = hasher.hash_two(&hasher.hash_two(&addr, &randomness)?, &nullifier)?;
    end_timer!(timer);

    let timer = start_timer!(|| "Computing Nullifier Hash");
    let nullifier_hash = hasher.hash_two(&nullifier, &vote_id)?;
    end_timer!(timer);

    let timer = start_timer!(|| "Computing Merkle Tree Root And Leafs");
    commitment_tree.insert_batch(
        &BTreeMap::from_iter(
            (0..current_participant)
                .enumerate()
                .into_iter()
                .map(|(i, v)| {
                    (
                        i as u32,
                        match v {
                            v if v == current_participant - 1 => commitment,
                            _ => E::Fr::rand(rng),
                        },
                    )
                })
                .rev(),
        ),
        &hasher,
    )?;
    end_timer!(timer);

    let proof = Groth16::<E>::prove(
        &pk,
        VotingCommitmentCircuitNoWhitelistGeneric::<E::Fr, PoseidonGadget<E::Fr>, 12> {
            hasher: hasher.clone(),
            nullifier_hash,
            vote_id,
            commitment_root: commitment_tree.root(),
            address: addr,
            randomness,
            nullifier,
            commitment_proof: commitment_tree
                .generate_membership_proof((current_participant - 1) as u64),
        },
        rng,
    )?;

    let verified = Groth16::verify(
        &vk,
        &[commitment_tree.root(), nullifier_hash, vote_id],
        &proof,
    )?;

    assert!(verified);

    Ok(())
}
