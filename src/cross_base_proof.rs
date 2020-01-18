use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

const CROSS_BASE_PROOF_MESSAGE: &[u8] = b"cross base proof signature\0";

pub struct CrossBaseProof {
    r_val: RistrettoPoint,
    l_val: RistrettoPoint,
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
        let pubkey1 = secret * base1;
        let pubkey2 = secret * base2;
        let hram = Scalar::from_hash(
            Sha512::new()
                .chain(r_val.compress().as_bytes())
                .chain(l_val.compress().as_bytes())
                .chain(pubkey1.compress().as_bytes())
                .chain(pubkey2.compress().as_bytes())
                .chain(CROSS_BASE_PROOF_MESSAGE),
        );
        let s_val = a_val + hram * secret;
        CrossBaseProof {
            r_val,
            l_val,
            s_val,
        }
    }

    pub fn validate(
        &self,
        base1: &RistrettoPoint,
        pubkey1: &RistrettoPoint,
        base2: &RistrettoPoint,
        pubkey2: &RistrettoPoint,
    ) -> Result<(), ()> {
        let hram = Scalar::from_hash(
            Sha512::new()
                .chain(self.r_val.compress().as_bytes())
                .chain(self.l_val.compress().as_bytes())
                .chain(pubkey1.compress().as_bytes())
                .chain(pubkey2.compress().as_bytes())
                .chain(CROSS_BASE_PROOF_MESSAGE),
        );
        let expected_sb1 = self.r_val + hram * pubkey1;
        if expected_sb1 != self.s_val * base1 {
            return Err(());
        }
        let expected_sb2 = self.l_val + hram * pubkey2;
        if expected_sb2 != self.s_val * base2 {
            return Err(());
        }
        Ok(())
    }
}
