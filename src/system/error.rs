use thiserror::Error;

#[derive(Debug, Error)]
pub enum SystemError {
    #[error(transparent)]
    Ark(#[from] Box<dyn ark_std::error::Error>),

    #[error(transparent)]
    Synthesis(#[from] ark_relations::r1cs::SynthesisError),

    #[error(transparent)]
    Poseidon(#[from] arkworks_native_gadgets::poseidon::PoseidonError),

    #[error("Invalid Proof")]
    InvalidProof,

    #[error("Used Nullifier")]
    UsedNullifier,
}

impl PartialEq for SystemError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ark(l0), Self::Ark(r0)) => l0.to_string() == r0.to_string(),
            (Self::Synthesis(l0), Self::Synthesis(r0)) => l0 == r0,
            (Self::Poseidon(l0), Self::Poseidon(r0)) => l0.to_string() == r0.to_string(),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}
