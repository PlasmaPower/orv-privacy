use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// Proof of knowledge for an ElGamal ciphertext.
/// From https://eprint.iacr.org/2019/319.pdf Figure 3
/// However, I've changed this to be a bit more space efficient
/// by sending the challenge instead of A and B. During validation,
/// we reconstruct A and B, then validate the challenge with them.
pub struct ElgamalProof {
    challenge: Scalar,
    /// Referred to as z1 in the paper
    s1: Scalar,
    /// Referred to as z2 in the paper
    s2: Scalar,
}

impl ElgamalProof {
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        blinding_key: Scalar,
        blinding_base: &RistrettoPoint,
        balance: u64,
        decryption_key_base: &RistrettoPoint,
    ) -> ElgamalProof {
        // referred to as "a" in the paper
        let r1 = Scalar::random(rng);
        // referred to as "b" in the paper
        let r2_added = Scalar::random(rng);
        let r1_pub = r1 * decryption_key_base;
        let r2_pub = r1 * blinding_base + &r2_added * &RISTRETTO_BASEPOINT_TABLE;
        let challenge = Scalar::from_hash(
            Sha512::new()
                .chain(r1_pub.compress().as_bytes())
                .chain(r2_pub.compress().as_bytes()),
        );
        let s1 = r1 + challenge * blinding_key;
        let s2 = r2_added + challenge * Scalar::from(balance);
        ElgamalProof { challenge, s1, s2 }
    }

    pub fn verify(
        &self,
        commitment: &RistrettoPoint,
        decryption_key: &RistrettoPoint,
        blinding_base: &RistrettoPoint,
        decryption_key_base: &RistrettoPoint,
    ) -> Result<(), ()> {
        let r1_pub = self.s1 * decryption_key_base - self.challenge * decryption_key;
        let r2_pub = self.s1 * blinding_base + &self.s2 * &RISTRETTO_BASEPOINT_TABLE
            - self.challenge * commitment;
        let expected_challenge = Scalar::from_hash(
            Sha512::new()
                .chain(r1_pub.compress().as_bytes())
                .chain(r2_pub.compress().as_bytes()),
        );
        if expected_challenge == self.challenge {
            Ok(())
        } else {
            Err(())
        }
    }
}
