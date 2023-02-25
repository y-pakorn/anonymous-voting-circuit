use std::error::Error;

use ark_bn254::{Bn254 as Pairing, Fr};
use ark_ff::UniformRand;
use ark_std::{end_timer, start_timer};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
use rand::thread_rng;

use crate::{
    benchmark::{run_commitment_circuit, run_registration_circuit},
    utils::setup_params,
};

#[test]
fn poseidon_exp_hash() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();
    let poseidon_x3_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 3, 3));
    let poseidon_x5_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 3));
    let poseidon_x17_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 17, 3));

    let left = Fr::rand(rng);
    let right = Fr::rand(rng);

    let timer = start_timer!(|| "Poseidon x3 width 3");
    let _ = poseidon_x3_3.hash_two(&left, &right)?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x5 width 3");
    let _ = poseidon_x5_3.hash_two(&left, &right)?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x17 width 3");
    let _ = poseidon_x17_3.hash_two(&left, &right)?;
    end_timer!(timer);

    Ok(())
}

#[test]
fn poseidon_exp_register() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();
    let poseidon_x3_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 3, 3));
    let poseidon_x5_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 3));
    let poseidon_x17_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 17, 3));

    let timer = start_timer!(|| "Poseidon x3 width 3");
    run_registration_circuit::<Pairing, _>(poseidon_x3_3, rng, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x5 width 3");
    run_registration_circuit::<Pairing, _>(poseidon_x5_3, rng, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x17 width 3");
    run_registration_circuit::<Pairing, _>(poseidon_x17_3, rng, "")?;
    end_timer!(timer);

    Ok(())
}

#[test]
fn poseidon_exp_commitment_at_1() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();
    let poseidon_x3_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 3, 3));
    let poseidon_x5_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 3));
    let poseidon_x17_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 17, 3));

    let timer = start_timer!(|| "Poseidon x3 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x3_3, rng, 1, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x5 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x5_3, rng, 1, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x17 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x17_3, rng, 1, "")?;
    end_timer!(timer);

    Ok(())
}

#[test]
fn poseidon_exp_commitment_at_1500() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();
    let poseidon_x3_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 3, 3));
    let poseidon_x5_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 3));
    let poseidon_x17_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 17, 3));

    let timer = start_timer!(|| "Poseidon x3 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x3_3, rng, 1501, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x5 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x5_3, rng, 1501, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x17 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x17_3, rng, 1501, "")?;
    end_timer!(timer);

    Ok(())
}

#[test]
fn poseidon_exp_commitment_at_4000() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();
    let poseidon_x3_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 3, 3));
    let poseidon_x5_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 3));
    let poseidon_x17_3 = Poseidon::<Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 17, 3));

    let timer = start_timer!(|| "Poseidon x3 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x3_3, rng, 4001, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x5 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x5_3, rng, 4001, "")?;
    end_timer!(timer);

    let timer = start_timer!(|| "Poseidon x17 width 3");
    run_commitment_circuit::<Pairing, _>(poseidon_x17_3, rng, 4001, "")?;
    end_timer!(timer);

    Ok(())
}
