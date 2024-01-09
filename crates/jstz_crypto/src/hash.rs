use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Blake2b([u8; 32]);

impl ToString for Blake2b {
    fn to_string(&self) -> String {
        hex::encode(self.0)
    }
}

#[cfg(all(target_os = "hermit", target_arch = "riscv64"))]
unsafe fn blake2b_hash(msg: *const u8, msg_len: u64) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    let out = result.as_mut_ptr();

    core::arch::asm!(
        "ecall",
        in("a6") 0x07,
        in("a7") 0x0A000000u64,
        in("a0") out,
        in("a1") msg,
        in("a2") msg_len,
    );

    result
}

impl<'a> From<&'a [u8]> for Blake2b {
    fn from(data: &'a [u8]) -> Self {
        #[cfg(not(all(target_os = "hermit", target_arch = "riscv64")))]
        let digest = tezos_crypto_rs::blake2b::digest_256(data).unwrap();

        #[cfg(all(target_os = "hermit", target_arch = "riscv64"))]
        let digest = unsafe { blake2b_hash(data.as_ptr(), data.len() as u64) };

        Self(digest.try_into().unwrap())
    }
}

impl<'a> From<&'a Vec<u8>> for Blake2b {
    fn from(data: &'a Vec<u8>) -> Self {
        let data = data.as_slice();
        Self::from(data)
    }
}

impl AsRef<[u8]> for Blake2b {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Blake2b {
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}
