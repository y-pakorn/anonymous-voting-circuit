use std::{borrow::Borrow, fmt::Debug, marker::PhantomData};

use ark_crypto_primitives::encryption::{
    elgamal::{constraints::OutputVar, ElGamal, SecretKey},
    AsymmetricEncryptionScheme,
};
use ark_ec::ProjectiveCurve;
use ark_ff::{to_bytes, Field, PrimeField, Zero};
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, CurveVar, EqGadget, GroupOpsBounds},
    uint8::UInt8,
    ToBitsGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use derivative::Derivative;

use crate::utils::ConstraintF;

pub trait AsymmetricDecryptionGadget<C: AsymmetricEncryptionScheme, ConstraintF: Field> {
    type OutputVar: AllocVar<C::Ciphertext, ConstraintF>
        + EqGadget<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type SecretKeyVar: AllocVar<C::SecretKey, ConstraintF> + Clone;
    type DecryptOutputVar: AllocVar<C::Plaintext, ConstraintF> + Clone;

    fn decrypt(
        ciphertext: &Self::OutputVar,
        secret_key: &Self::SecretKeyVar,
    ) -> Result<Self::DecryptOutputVar, SynthesisError>;
}

#[derive(Clone, Debug)]
pub struct SecretKeyVar<F: Field>(pub Vec<UInt8<F>>);

impl<C, F> AllocVar<SecretKey<C>, F> for SecretKeyVar<F>
where
    C: ProjectiveCurve,
    F: PrimeField,
{
    fn new_variable<T: Borrow<SecretKey<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f()
            .map(|b| b.borrow().0)
            .unwrap_or_else(|_| C::ScalarField::zero())]
        .unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

pub type DecryptOutput<C> = <C as ProjectiveCurve>::Affine;

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct DecryptOutputVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub decrypted: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GC> EqGadget<ConstraintF<C>> for DecryptOutputVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn is_eq(
        &self,
        other: &Self,
    ) -> Result<ark_r1cs_std::prelude::Boolean<ConstraintF<C>>, SynthesisError> {
        self.decrypted.is_eq(&other.decrypted)
    }
}

impl<C, GG> AllocVar<DecryptOutput<C>, ConstraintF<C>> for DecryptOutputVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<DecryptOutput<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let decrypted = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            decrypted,
            _curve: PhantomData,
        })
    }
}

pub struct ElGamalDecGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> AsymmetricDecryptionGadget<ElGamal<C>, ConstraintF<C>> for ElGamalDecGadget<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    type OutputVar = OutputVar<C, GG>;
    type DecryptOutputVar = DecryptOutputVar<C, GG>;
    type SecretKeyVar = SecretKeyVar<ConstraintF<C>>;

    fn decrypt(
        ciphertext: &Self::OutputVar,
        secret_key: &Self::SecretKeyVar,
    ) -> Result<Self::DecryptOutputVar, SynthesisError> {
        let c1 = &ciphertext.c1;
        let c2 = &ciphertext.c2;

        let s: GG = c1.scalar_mul_le(secret_key.0.to_bits_le()?.iter())?;
        let s_inv = s.negate()?;

        let m = c2 + s_inv;

        Ok(DecryptOutputVar {
            decrypted: m,
            _curve: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::encryption::{
        elgamal::{constraints::ElGamalEncGadget, ElGamal, Randomness},
        AsymmetricEncryptionGadget, AsymmetricEncryptionScheme,
    };
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};

    use super::*;

    #[test]
    fn test_elgamal_gadget() {
        let rng = &mut test_rng();

        type MyEnc = ElGamal<JubJub>;
        type MyGadget = ElGamalEncGadget<JubJub, EdwardsVar>;
        type MyDecGadget = ElGamalDecGadget<JubJub, EdwardsVar>;

        // compute primitive result
        let parameters = MyEnc::setup(rng).unwrap();
        let (pk, sk) = MyEnc::keygen(&parameters, rng).unwrap();
        let msg = JubJub::rand(rng).into();
        let randomness = Randomness::rand(rng);
        let primitive_result = MyEnc::encrypt(&parameters, &pk, &msg, &randomness).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness),
            )
            .unwrap();
        let parameters_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                &parameters,
            )
            .unwrap();
        let msg_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "gadget_message"),
                || Ok(&msg),
            )
            .unwrap();
        let pk_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&pk),
            )
            .unwrap();

        // use gadget
        let result_var =
            MyGadget::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::OutputVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(&primitive_result),
            )
            .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(primitive_result.0, result_var.c1.value().unwrap());
        assert_eq!(primitive_result.1, result_var.c2.value().unwrap());
        assert!(cs.is_satisfied().unwrap());

        let primitive_decrypted = MyEnc::decrypt(&parameters, &sk, &primitive_result).unwrap();

        let sk_var =
            <MyDecGadget as AsymmetricDecryptionGadget<MyEnc, Fq>>::SecretKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&sk),
            )
            .unwrap();

        let decrypt_result_var = MyDecGadget::decrypt(&result_var, &sk_var).unwrap();
        let decrypt_expected_var =
            <MyDecGadget as AsymmetricDecryptionGadget<MyEnc, Fq>>::DecryptOutputVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(&primitive_decrypted),
            )
            .unwrap();

        decrypt_result_var
            .enforce_equal(&decrypt_expected_var)
            .unwrap();
    }
}
