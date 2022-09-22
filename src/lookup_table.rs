use std::{collections::HashMap, marker::PhantomData};

use ark_ec::{AffineCurve, ProjectiveCurve};

pub struct LookupTable<A: AffineCurve> {
    pub table: HashMap<A, u64>,
    _phantom: PhantomData<A>,
}

impl<A: AffineCurve> LookupTable<A> {
    pub fn new(values: impl IntoIterator<Item = u64>) -> Self {
        let generator = A::prime_subgroup_generator();
        Self {
            table: HashMap::from_iter(values.into_iter().map(|e| {
                (
                    <A::Projective as ProjectiveCurve>::into_affine(
                        &generator.mul(<A::ScalarField as From<u64>>::from(e)),
                    ),
                    e,
                )
            })),
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::Fr;
    use ark_crypto_primitives::encryption::{
        elgamal::{ElGamal, Randomness},
        AsymmetricEncryptionScheme,
    };
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    use crate::lookup_table::LookupTable;

    type ElG = ElGamal<EdwardsProjective>;

    #[test]
    fn lookup_elgamal() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        let param = ElG::setup(&mut rng)?;
        let (pk, sk) = ElG::keygen(&param, &mut rng)?;
        let randomness = Randomness::<EdwardsProjective>::rand(&mut rng);

        let one = EdwardsAffine::prime_subgroup_generator()
            .mul(Fr::from(1))
            .into_affine();

        let one_enc = ElG::encrypt(&param, &pk, &one, &randomness)?;
        let dec = ElG::decrypt(&param, &sk, &(one_enc.0 + one_enc.0, one_enc.1 + one_enc.1))?;

        let table = LookupTable::<EdwardsAffine>::new(0..10);

        assert_eq!(table.table.get(&dec), Some(&2));

        Ok(())
    }
}
