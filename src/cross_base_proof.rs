use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

const CROSS_BASE_PROOF_MESSAGE: &[u8] = b"cross base proof signature\0";

/// Allows one to verify that for points `G`, `H`, `A`, and `B`,
/// the prover knows some `s` for which `A = s*G` and `B = s*H`.
/// I.e. `A` and `B` are the public keys for the same secret key
/// in the basepoints `G` and `H`.
pub struct CrossBaseProof {
    c_val: Scalar,
    s_val: Scalar,
}

impl CrossBaseProof {
    pub fn new<R>(
        rng: &mut R,
        base1: &RistrettoPoint,
        base2: &RistrettoPoint,
        secret: Scalar,
    ) -> CrossBaseProof
    where
        R: RngCore + CryptoRng,
    {
        let a_val = Scalar::random(rng);
        let r_val = a_val * base1;
        let l_val = a_val * base2;
        let c_val = Scalar::from_hash(
            Sha512::new()
                .chain(r_val.compress().as_bytes())
                .chain(l_val.compress().as_bytes())
                .chain(CROSS_BASE_PROOF_MESSAGE),
        );
        let s_val = a_val + c_val * secret;
        CrossBaseProof { c_val, s_val }
    }

    pub fn validate(
        &self,
        base1: &RistrettoPoint,
        pubkey1: &RistrettoPoint,
        base2: &RistrettoPoint,
        pubkey2: &RistrettoPoint,
    ) -> Result<(), ()> {
        let r_val = self.s_val * base1 - self.c_val * pubkey1;
        let l_val = self.s_val * base2 - self.c_val * pubkey2;
        let expected_c = Scalar::from_hash(
            Sha512::new()
                .chain(r_val.compress().as_bytes())
                .chain(l_val.compress().as_bytes())
                .chain(CROSS_BASE_PROOF_MESSAGE),
        );
        if self.c_val == expected_c {
            Ok(())
        } else {
            Err(())
        }
    }
}
