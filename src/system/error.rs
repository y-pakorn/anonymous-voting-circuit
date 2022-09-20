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
