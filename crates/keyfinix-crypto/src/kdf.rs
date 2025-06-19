pub use argon2::ParamsBuilder as Argon2ParamsBuilder;
use argon2::{Argon2, Block};
use zeroize::Zeroizing;

pub fn derive_persist_key(input: &[u8], salt: &[u8], output: &mut [u8]) -> argon2::Result<()> {
    derive_key(input, salt, output, Hardness::Persist)
}

pub fn derive_user_prehash_key(input: &[u8], salt: &[u8], output: &mut [u8]) -> argon2::Result<()> {
    derive_key(input, salt, output, Hardness::UserPrehash)
}

pub enum Hardness {
    /// Strength for client-side pre-hashing.
    UserPrehash,
    /// Strength for protecting persistent, static secrets.
    Persist,
}

pub fn derive_key(
    input: &[u8],
    salt: &[u8],
    output: &mut [u8],
    hardness: Hardness,
) -> argon2::Result<()> {
    #[cfg(not(coverage))]
    let params = match hardness {
        Hardness::UserPrehash => argon2::ParamsBuilder::new()
            .m_cost(16384)
            .t_cost(4)
            .p_cost(2)
            .output_len(output.len())
            .build()
            .unwrap(),
        Hardness::Persist => argon2::ParamsBuilder::new()
            .m_cost(64 << 10)
            .t_cost(8)
            .p_cost(2)
            .output_len(output.len())
            .build()
            .unwrap(),
    };
    #[cfg(coverage)]
    let params = match argon2::Params::new(128, 1, 1, Some(32)) {
        Ok(p) => p,
        Err(_) => unreachable!(),
    };

    let mut mem = Zeroizing::new(vec![Block::default(); params.block_count()].into_boxed_slice());

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2.hash_password_into_with_memory(input, salt, output, &mut mem)
}
