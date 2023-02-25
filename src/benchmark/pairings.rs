use std::error::Error;

use ark_std::{end_timer, start_timer};
use arkworks_native_gadgets::poseidon::Poseidon;
use rand::thread_rng;

use crate::{
    benchmark::{run_commitment_circuit, run_registration_circuit},
    utils::setup_params,
};

#[test]
fn pairings_register() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();

    let timer = start_timer!(|| "BN254");
    run_registration_circuit::<ark_bn254::Bn254, _>(
        Poseidon::<ark_bn254::Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 5)),
        rng,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-381");
    run_registration_circuit::<ark_bls12_381::Bls12_381, _>(
        Poseidon::<ark_bls12_381::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-377");
    run_registration_circuit::<ark_bls12_377::Bls12_377, _>(
        Poseidon::<ark_bls12_377::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        "",
    )?;
    end_timer!(timer);

    Ok(())
}

#[test]
fn pairings_commitment_at_1() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();

    let timer = start_timer!(|| "BN254");
    run_commitment_circuit::<ark_bn254::Bn254, _>(
        Poseidon::<ark_bn254::Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 5)),
        rng,
        1,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-381");
    run_commitment_circuit::<ark_bls12_381::Bls12_381, _>(
        Poseidon::<ark_bls12_381::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        1,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-377");
    run_commitment_circuit::<ark_bls12_377::Bls12_377, _>(
        Poseidon::<ark_bls12_377::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        1,
        "",
    )?;
    end_timer!(timer);

    Ok(())
}

#[test]
fn pairings_commitment_at_1501() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();

    let timer = start_timer!(|| "BN254");
    run_commitment_circuit::<ark_bn254::Bn254, _>(
        Poseidon::<ark_bn254::Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 5)),
        rng,
        1501,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-381");
    run_commitment_circuit::<ark_bls12_381::Bls12_381, _>(
        Poseidon::<ark_bls12_381::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        1501,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-377");
    run_commitment_circuit::<ark_bls12_377::Bls12_377, _>(
        Poseidon::<ark_bls12_377::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        1501,
        "",
    )?;
    end_timer!(timer);

    Ok(())
}

#[test]
fn pairings_commitment_at_4001() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();

    let timer = start_timer!(|| "BN254");
    run_commitment_circuit::<ark_bn254::Bn254, _>(
        Poseidon::<ark_bn254::Fr>::new(setup_params(arkworks_utils::Curve::Bn254, 5, 5)),
        rng,
        4001,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-381");
    run_commitment_circuit::<ark_bls12_381::Bls12_381, _>(
        Poseidon::<ark_bls12_381::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        4001,
        "",
    )?;
    end_timer!(timer);

    let timer = start_timer!(|| "BLS12-377");
    run_commitment_circuit::<ark_bls12_377::Bls12_377, _>(
        Poseidon::<ark_bls12_377::Fr>::new(setup_params(arkworks_utils::Curve::Bls381, 5, 5)),
        rng,
        4001,
        "",
    )?;
    end_timer!(timer);

    Ok(())
}
