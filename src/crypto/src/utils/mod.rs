use data_encoding::HEXLOWER;
use ring::rand::{self, SecureRandom};
use std::str;

pub struct HashUtils;

impl HashUtils {
    pub fn hash(_algorithm: &str, _data: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

pub fn generate_random_bytes(size: u32) -> String {
    let mut random_vec = Vec::<u8>::new();
    random_vec.resize(size as usize, 0);
    let rng = rand::SystemRandom::new();
    rng.fill(&mut random_vec).unwrap();
    HEXLOWER.encode(&random_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdbdk() {
        let password = generate_random_bytes(32);
        assert_eq!((password.len() as u32 > 32), true);
    }
}
