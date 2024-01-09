use crate::{public_key::PublicKey, Error, Result};
use serde::{Deserialize, Serialize};
use tezos_crypto_rs::PublicKeySignatureVerifier;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Signature {
    Ed25519(tezos_crypto_rs::hash::Signature),
}

#[cfg(all(target_os = "hermit", target_arch = "riscv64"))]
unsafe fn ed25519_verify(
    pk: *const u8,
    pk_len: u64,
    sig: *const u8,
    sig_len: u64,
    msg: *const u8,
    msg_len: u64,
) -> bool {
    let result: u64;

    core::arch::asm!(
        "ecall",
        in("a6") 0x05,
        in("a7") 0x0A000000u64,
        in("a0") pk,
        in("a1") pk_len,
        in("a2") sig,
        in("a3") sig_len,
        in("a4") msg,
        in("a5") msg_len,
        lateout("a0") result
    );

    result != 0
}

impl Signature {
    pub fn verify(&self, public_key: &PublicKey, message: &[u8]) -> Result<()> {
        match (self, public_key) {
            (Signature::Ed25519(sig), PublicKey::Ed25519(pk)) => {
                #[cfg(not(all(target_os = "hermit", target_arch = "riscv64")))]
                let result = pk.verify_signature(sig, message).unwrap();

                let pk_bytes = pk.0.as_slice();
                let sig_bytes = sig.0.as_slice();

                #[cfg(all(target_os = "hermit", target_arch = "riscv64"))]
                let result = unsafe {
                    ed25519_verify(
                        pk_bytes.as_ptr(),
                        pk_bytes.len() as u64,
                        sig_bytes.as_ptr(),
                        sig_bytes.len() as u64,
                        message.as_ptr(),
                        message.len() as u64,
                    )
                };

                if result {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }
}
