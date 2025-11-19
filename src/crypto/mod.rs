//! Quantum-resistant cryptography module
//!
//! Uses hybrid encryption:
//! - ML-KEM-1024 (Kyber) for post-quantum key encapsulation
//! - X25519 for classical ECDH key exchange
//! - ChaCha20-Poly1305 for symmetric encryption
//! - BLAKE3 for key derivation

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// Hybrid public key (X25519 + Kyber)
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub x25519: [u8; 32],
    pub kyber: Vec<u8>,
}

/// Hybrid secret key (X25519 + Kyber)
pub struct HybridSecretKey {
    pub x25519: StaticSecret,
    pub kyber: kyber1024::SecretKey,
}

/// Hybrid keypair
pub struct HybridKeypair {
    pub public: HybridPublicKey,
    pub secret: HybridSecretKey,
}

/// Encapsulated keys for key exchange
#[derive(Clone, Serialize, Deserialize)]
pub struct EncapsulatedKey {
    pub x25519_public: [u8; 32],
    pub kyber_ciphertext: Vec<u8>,
}

/// Session keys derived from key exchange
pub struct SessionKeys {
    pub encrypt_key: [u8; 32],
    pub decrypt_key: [u8; 32],
    pub nonce_base: [u8; 12],
}

impl HybridKeypair {
    /// Generate a new hybrid keypair
    pub fn generate() -> Self {
        // Generate X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate Kyber keypair
        let (kyber_public, kyber_secret) = kyber1024::keypair();

        HybridKeypair {
            public: HybridPublicKey {
                x25519: x25519_public.to_bytes(),
                kyber: kyber_public.as_bytes().to_vec(),
            },
            secret: HybridSecretKey {
                x25519: x25519_secret,
                kyber: kyber_secret,
            },
        }
    }

    /// Serialize public key for transport
    pub fn public_key_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.public).expect("Failed to serialize public key")
    }

    /// Serialize secret key for storage
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.secret.x25519.as_bytes());
        bytes.extend_from_slice(self.secret.kyber.as_bytes());
        bytes
    }

    /// Load keypair from bytes
    pub fn from_bytes(public_bytes: &[u8], secret_bytes: &[u8]) -> Result<Self> {
        let public: HybridPublicKey = bincode::deserialize(public_bytes)?;

        if secret_bytes.len() < 32 {
            return Err(anyhow!("Invalid secret key length"));
        }

        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&secret_bytes[..32]);
        let x25519_secret = StaticSecret::from(x25519_bytes);

        let kyber_secret = kyber1024::SecretKey::from_bytes(&secret_bytes[32..])
            .map_err(|_| anyhow!("Invalid Kyber secret key"))?;

        Ok(HybridKeypair {
            public,
            secret: HybridSecretKey {
                x25519: x25519_secret,
                kyber: kyber_secret,
            },
        })
    }
}

/// Perform key encapsulation (client side)
pub fn encapsulate(peer_public: &HybridPublicKey) -> Result<(EncapsulatedKey, [u8; 64])> {
    // X25519 key exchange
    let x25519_ephemeral = EphemeralSecret::random_from_rng(rand::thread_rng());
    let x25519_public = X25519PublicKey::from(&x25519_ephemeral);

    let peer_x25519 = X25519PublicKey::from(peer_public.x25519);
    let x25519_shared = x25519_ephemeral.diffie_hellman(&peer_x25519);

    // Kyber encapsulation
    let kyber_public = kyber1024::PublicKey::from_bytes(&peer_public.kyber)
        .map_err(|_| anyhow!("Invalid Kyber public key"))?;
    let (kyber_shared, kyber_ciphertext) = kyber1024::encapsulate(&kyber_public);

    // Combine shared secrets using BLAKE3
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"QuantumShieldVPN-v1");
    hasher.update(x25519_shared.as_bytes());
    hasher.update(kyber_shared.as_bytes());

    let mut combined_secret = [0u8; 64];
    hasher.finalize_xof().fill(&mut combined_secret);

    let encapsulated = EncapsulatedKey {
        x25519_public: x25519_public.to_bytes(),
        kyber_ciphertext: kyber_ciphertext.as_bytes().to_vec(),
    };

    Ok((encapsulated, combined_secret))
}

/// Perform key decapsulation (server side)
pub fn decapsulate(
    encapsulated: &EncapsulatedKey,
    secret_key: &HybridSecretKey,
) -> Result<[u8; 64]> {
    // X25519 key exchange
    let peer_x25519 = X25519PublicKey::from(encapsulated.x25519_public);
    let x25519_shared = secret_key.x25519.diffie_hellman(&peer_x25519);

    // Kyber decapsulation
    let kyber_ciphertext = kyber1024::Ciphertext::from_bytes(&encapsulated.kyber_ciphertext)
        .map_err(|_| anyhow!("Invalid Kyber ciphertext"))?;
    let kyber_shared = kyber1024::decapsulate(&kyber_ciphertext, &secret_key.kyber);

    // Combine shared secrets using BLAKE3
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"QuantumShieldVPN-v1");
    hasher.update(x25519_shared.as_bytes());
    hasher.update(kyber_shared.as_bytes());

    let mut combined_secret = [0u8; 64];
    hasher.finalize_xof().fill(&mut combined_secret);

    Ok(combined_secret)
}

/// Derive session keys from shared secret
pub fn derive_session_keys(shared_secret: &[u8; 64], is_initiator: bool) -> SessionKeys {
    let mut hasher = blake3::Hasher::new_derive_key("QuantumShieldVPN-SessionKeys-v1");
    hasher.update(shared_secret);

    let mut key_material = [0u8; 76]; // 32 + 32 + 12
    hasher.finalize_xof().fill(&mut key_material);

    let (encrypt_key, decrypt_key) = if is_initiator {
        (
            <[u8; 32]>::try_from(&key_material[0..32]).unwrap(),
            <[u8; 32]>::try_from(&key_material[32..64]).unwrap(),
        )
    } else {
        (
            <[u8; 32]>::try_from(&key_material[32..64]).unwrap(),
            <[u8; 32]>::try_from(&key_material[0..32]).unwrap(),
        )
    };

    SessionKeys {
        encrypt_key,
        decrypt_key,
        nonce_base: <[u8; 12]>::try_from(&key_material[64..76]).unwrap(),
    }
}

/// Encrypt data with ChaCha20-Poly1305
pub fn encrypt(key: &[u8; 32], nonce_counter: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

    // Create nonce from counter
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))
}

/// Decrypt data with ChaCha20-Poly1305
pub fn decrypt(key: &[u8; 32], nonce_counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

    // Create nonce from counter
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        // Server generates keypair
        let server_keypair = HybridKeypair::generate();

        // Client encapsulates
        let (encapsulated, client_secret) = encapsulate(&server_keypair.public).unwrap();

        // Server decapsulates
        let server_secret = decapsulate(&encapsulated, &server_keypair.secret).unwrap();

        // Secrets should match
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn test_encryption() {
        let key = [42u8; 32];
        let plaintext = b"Hello, Quantum World!";

        let ciphertext = encrypt(&key, 1, plaintext).unwrap();
        let decrypted = decrypt(&key, 1, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_session_keys() {
        let secret = [0u8; 64];

        let client_keys = derive_session_keys(&secret, true);
        let server_keys = derive_session_keys(&secret, false);

        // Client encrypt = Server decrypt
        assert_eq!(client_keys.encrypt_key, server_keys.decrypt_key);
        assert_eq!(client_keys.decrypt_key, server_keys.encrypt_key);
    }
}
