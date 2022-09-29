use ark_bls12_381::Fr;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::ConstraintSynthesizer;
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};

pub struct CommitmentRegistrationCircuit {
    // Public
    pub commitment: Fr,
    pub address: Fr,

    // Secret
    pub randomness: Fr,
    pub nullifier: Fr,

    // Utils
    pub hasher: <PoseidonGadget<Fr> as FieldHasherGadget<Fr>>::Native,
}

impl ConstraintSynthesizer<Fr> for CommitmentRegistrationCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        // Hasher
        let hasher_var: PoseidonGadget<Fr> =
            FieldHasherGadget::<Fr>::from_native(&mut cs.clone(), self.hasher)?;

        // Public
        let commitment_var = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        let address_var = FpVar::new_input(cs.clone(), || Ok(self.address))?;

        // Secret
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(self.randomness))?;
        let nullifier_var = FpVar::new_witness(cs, || Ok(self.nullifier))?;

        let secret = hasher_var.hash_two(&address_var, &randomness_var)?;
        let commitment = hasher_var.hash_two(&secret, &nullifier_var)?;

        commitment_var.enforce_equal(&commitment)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::{PrimeField, UniformRand};
    use ark_groth16::Groth16;
    use ark_std::test_rng;
    use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
    use arkworks_utils::Curve;

    use crate::utils::setup_params;

    use super::CommitmentRegistrationCircuit;

    #[test]
    #[ignore = "Long compute time ~3.14s"]
    fn registration_verify_simple() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();
        let poseidon = Poseidon::<Fr>::new(setup_params(Curve::Bls381, 5, 5));

        let (pk, vk) = Groth16::<Bls12_381>::setup(
            CommitmentRegistrationCircuit {
                hasher: poseidon.clone(),
                address: Fr::rand(&mut rng),
                commitment: Fr::rand(&mut rng),
                randomness: Fr::rand(&mut rng),
                nullifier: Fr::rand(&mut rng),
            },
            &mut rng,
        )?;

        let addr = Fr::from_be_bytes_mod_order(b"someassaddr");
        let randomness = Fr::rand(&mut rng);
        let nullifier = Fr::rand(&mut rng);

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
