use std::error::Error;

use ark_std::{end_timer, start_timer};
use arkworks_native_gadgets::poseidon::Poseidon;
use rand::thread_rng;

use crate::{benchmark::run_registration_circuit, utils::setup_params};

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
