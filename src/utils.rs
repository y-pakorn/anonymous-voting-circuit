use ark_ec::ProjectiveCurve;
use ark_ff::{Field, PrimeField};
use arkworks_native_gadgets::poseidon::{sbox::PoseidonSbox, PoseidonParameters};
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};

pub type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
    let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    match (curve, exp, width) {
        (arkworks_utils::Curve::Bn254, 17, 3) => PoseidonParameters {
            mds_matrix: mds_f,
            round_keys: rounds_f.into_iter().cycle().take(195).collect(),
            full_rounds: pos_data.full_rounds,
            partial_rounds: pos_data.partial_rounds,
            sbox: PoseidonSbox(pos_data.exp),
            width: pos_data.width,
        },
        _ => PoseidonParameters {
            mds_matrix: mds_f,
            round_keys: rounds_f,
            full_rounds: pos_data.full_rounds,
            partial_rounds: pos_data.partial_rounds,
            sbox: PoseidonSbox(pos_data.exp),
            width: pos_data.width,
        },
    }
}
