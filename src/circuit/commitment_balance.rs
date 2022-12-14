use std::marker::PhantomData;

use ark_bls12_381::Fr;
use ark_crypto_primitives::encryption::{
    elgamal::{
        constraints::{
            ElGamalEncGadget, OutputVar, ParametersVar, PlaintextVar, PublicKeyVar, RandomnessVar,
        },
        Parameters as ElGamalParameters, Randomness as ElGamalRandomness,
    },
    AsymmetricEncryptionGadget,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    ToBitsGadget,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_r1cs_gadgets::{
    merkle_tree::PathVar,
    poseidon::{FieldHasherGadget, PoseidonGadget},
};

use crate::utils::ConstraintF;

pub type VotingCommitmentBalanceCircuit<const N: usize> =
    VotingCommitmentBalanceCircuitGeneric<EdwardsProjective, PoseidonGadget<Fr>, EdwardsVar, N>;

pub struct VotingCommitmentBalanceCircuitGeneric<
    C: ProjectiveCurve,
    HG: FieldHasherGadget<ConstraintF<C>>,
    CV: CurveVar<C, ConstraintF<C>>,
    const N: usize,
> where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Public
    pub commitment_root: ConstraintF<C>,
    pub whitelist_root: ConstraintF<C>,
    pub nullifier_hash: ConstraintF<C>,
    pub vote_id: ConstraintF<C>,
    pub elg_param: C::Affine,                      // affine
    pub elg_pk: C::Affine,                         // affine
    pub encrypted_balance: (C::Affine, C::Affine), // (affine, affine)

    // Secret
    // whitelist = H(addr, balance)
    // commitment = H(H(addr, randomness), nullifier)
    pub address: ConstraintF<C>,
    pub randomness: ConstraintF<C>,
    pub nullifier: ConstraintF<C>,
    pub commitment_proof: Path<ConstraintF<C>, HG::Native, N>,
    pub whitelist_proof: Path<ConstraintF<C>, HG::Native, N>,
    pub balance: ConstraintF<C>,
    pub balance_affine: C::Affine,
    pub elg_randomness: ElGamalRandomness<C>, // Scalar field in ed

    // Utils
    pub hasher: HG::Native,
    pub _p: PhantomData<CV>,
}

impl<
        C: ProjectiveCurve,
        HG: FieldHasherGadget<ConstraintF<C>>,
        CV: CurveVar<C, ConstraintF<C>>,
        const N: usize,
    > ConstraintSynthesizer<ConstraintF<C>> for VotingCommitmentBalanceCircuitGeneric<C, HG, CV, N>
where
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF<C>>,
    ) -> ark_relations::r1cs::Result<()> {
        // Constant
        //let generator_var =
        //EdwardsVar::new_constant(cs.clone(), C::Affine::prime_subgroup_generator())?;
        let generator_var: CV = <CV as AllocVar<_, _>>::new_constant(
            cs.clone(),
            <C::Affine as AffineCurve>::prime_subgroup_generator(),
        )?;

        // Hasher
        let hasher_var: HG = FieldHasherGadget::from_native(&mut cs.clone(), self.hasher)?;

        // Public
        let commitment_root_var = FpVar::new_input(cs.clone(), || Ok(self.commitment_root))?;
        let whitelist_root_var = FpVar::new_input(cs.clone(), || Ok(self.whitelist_root))?;
        let nullifier_hash_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier_hash))?;
        let vote_id_var = FpVar::new_input(cs.clone(), || Ok(self.vote_id))?;

        // Public ElGamal
        let elg_param_var = ParametersVar::<C, CV>::new_input(cs.clone(), || {
            Ok(ElGamalParameters {
                generator: self.elg_param,
            })
        })?;
        let elg_pk_var = PublicKeyVar::<C, CV>::new_input(cs.clone(), || Ok(self.elg_pk))?;
        let encrypted_balance =
            OutputVar::<C, CV>::new_input(cs.clone(), || Ok(self.encrypted_balance))?;

        // Secret
        let address_var = FpVar::new_witness(cs.clone(), || Ok(self.address))?;
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(self.randomness))?;
        let nullifier_var = FpVar::new_witness(cs.clone(), || Ok(self.nullifier))?;
        let commitment_proof_var =
            PathVar::<_, _, N>::new_witness(cs.clone(), || Ok(self.commitment_proof))?;
        let whitelist_proof_var =
            PathVar::<_, _, N>::new_witness(cs.clone(), || Ok(self.whitelist_proof))?;
        let balance_var = FpVar::new_witness(cs.clone(), || Ok(self.balance))?;
        let balance_plaintext_var =
            PlaintextVar::<C, CV>::new_witness(cs.clone(), || Ok(self.balance_affine))?;
        let elg_randomness_var = RandomnessVar::new_witness(cs, || Ok(self.elg_randomness))?;

        let secret = hasher_var.hash_two(&address_var, &randomness_var)?;
        let commitment = hasher_var.hash_two(&secret, &nullifier_var)?;
        let nullifier_hashed = hasher_var.hash_two(&nullifier_var, &vote_id_var)?;
        let whitelist_leaf = hasher_var.hash_two(&address_var, &balance_var)?;

        let balance_affine_calculated =
            generator_var.scalar_mul_le(balance_var.to_bits_le()?.iter())?;
        let balance_encrypted = ElGamalEncGadget::<C, CV>::encrypt(
            &elg_param_var,
            &balance_plaintext_var,
            &elg_randomness_var,
            &elg_pk_var,
        )?;

        let is_correct_whitelist = whitelist_proof_var.check_membership(
            &whitelist_root_var,
            &whitelist_leaf,
            &hasher_var,
        )?;
        let is_correct_commitment = commitment_proof_var.check_membership(
            &commitment_root_var,
            &commitment,
            &hasher_var,
        )?;

        // Check encrypted_balance = E(balance)
        encrypted_balance.enforce_equal(&balance_encrypted)?;

        // Check g * balance = balance_affine
        balance_affine_calculated.enforce_equal(&balance_plaintext_var.plaintext)?;

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
    use ark_crypto_primitives::{
        encryption::{
            elgamal::{ElGamal, Randomness},
            AsymmetricEncryptionScheme,
        },
        CircuitSpecificSetupSNARK, SNARK,
    };
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
    use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
    use ark_groth16::Groth16;
    use ark_std::test_rng;
    use arkworks_native_gadgets::{
        merkle_tree::SparseMerkleTree,
        poseidon::{FieldHasher, Poseidon},
    };
    use arkworks_utils::Curve;

    use crate::utils::setup_params;

    use super::VotingCommitmentBalanceCircuit;

    #[test]
    #[ignore = "Long compute time ~33.6s"]
    fn voting_commitment_balance_verify_simple() -> Result<(), Box<dyn Error>> {
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
            VotingCommitmentBalanceCircuit::<5> {
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
                encrypted_balance: (EdwardsAffine::rand(&mut rng), EdwardsAffine::rand(&mut rng)),
                balance: Fr::rand(&mut rng),
                balance_affine: EdwardsAffine::rand(&mut rng),
                elg_randomness: Randomness::rand(&mut rng),
                _p: std::marker::PhantomData,
            },
            &mut rng,
        )?;

        let elg_param = ElGamal::<EdwardsProjective>::setup(&mut rng)?;
        let (elg_pk, _sk) = ElGamal::keygen(&elg_param, &mut rng)?;
        let elg_randomness = Randomness::<EdwardsProjective>::rand(&mut rng);

        let addr = Fr::from_be_bytes_mod_order(b"someassaddr");
        let balance = Fr::from(100);
        let randomness = Fr::rand(&mut rng);
        let nullifier = Fr::rand(&mut rng);
        let vote_id = Fr::from(0);

        let balance_affine = EdwardsAffine::prime_subgroup_generator()
            .mul(balance)
            .into_affine();

        let encrypted_balance =
            ElGamal::encrypt(&elg_param, &elg_pk, &balance_affine, &elg_randomness)?;

        let nullifier_hash = poseidon.hash_two(&nullifier, &vote_id)?;
        let commitment = poseidon.hash_two(&poseidon.hash_two(&addr, &randomness)?, &nullifier)?;
        let whitelist_leaf = poseidon.hash_two(&addr, &balance)?;

        whitelist_tree.insert_batch(&BTreeMap::from_iter([(0, whitelist_leaf)]), &poseidon)?;
        commitment_tree.insert_batch(&BTreeMap::from_iter([(0, commitment)]), &poseidon)?;

        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            VotingCommitmentBalanceCircuit::<5> {
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
                elg_param: elg_param.generator,
                elg_pk,
                encrypted_balance,
                balance,
                balance_affine,
                elg_randomness,
                _p: std::marker::PhantomData,
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
                elg_param.generator.x,
                elg_param.generator.y,
                elg_pk.x,
                elg_pk.y,
                encrypted_balance.0.x,
                encrypted_balance.0.y,
                encrypted_balance.1.x,
                encrypted_balance.1.y,
            ],
            &proof,
        )?;

        assert!(verified);

        Ok(())
    }
}
