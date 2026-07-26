use rand::{rngs::SysRng, TryRng};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct UserKeyPair {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl UserKeyPair {
    pub fn generate() -> Self {
        let private_key = StaticSecret::random();
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    SysRng
        .try_fill_bytes(&mut buf)
        .expect("operating-system RNG failure");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_are_random() {
        let a = random_bytes::<32>();
        let b = random_bytes::<32>();
        assert_ne!(a, b);
    }

    #[test]
    fn random_bytes_have_expected_length() {
        assert_eq!(random_bytes::<16>().len(), 16);
        assert_eq!(random_bytes::<32>().len(), 32);
        assert_eq!(random_bytes::<64>().len(), 64);
    }

    #[test]
    fn user_keypair_generates_distinct_keys() {
        let kp1 = UserKeyPair::generate();
        let kp2 = UserKeyPair::generate();
        assert_ne!(kp1.public_key.as_bytes(), kp2.public_key.as_bytes());
    }
}
