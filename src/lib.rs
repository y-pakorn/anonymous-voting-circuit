mod circuit;
mod random_oracle;
mod signature;
mod utils;

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::{Fr as BlsFr, G1Affine, G1Projective};
    use ark_crypto_primitives::encryption::{
        elgamal::{ElGamal, Randomness},
        AsymmetricEncryptionScheme,
    };
    use ark_ec::AffineCurve;
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use ark_std::test_rng;

    type ElG = ElGamal<G1Projective>;

    #[test]
    fn test_elgamal_prim() -> Result<(), Box<dyn Error>> {
        let mut rng = test_rng();

        let param = ElG::setup(&mut rng)?;
        let (pk, sk) = ElG::keygen(&param, &mut rng)?;
        let randomness = Randomness::<G1Projective>::rand(&mut rng);

        let two_pnt =
            G1Affine::from_random_bytes(&BlsFr::from(2).into_repr().to_bytes_be()).unwrap();
        let two_enc = ElG::encrypt(&param, &pk, &two_pnt, &randomness)?;

        let dec = ElG::decrypt(&param, &sk, &(two_enc.0 + two_enc.0, two_enc.1 + two_enc.1))?
            .into_projective();

        assert_eq!(two_pnt + two_pnt, dec);

        Ok(())
    }
}
