/// Borromean ring signature based range proofs
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

const BITS: usize = 32;
const RANGE_PROOF_MESSAGE: &[u8] = b"range proof\0";

pub struct RangeProof {
    key_images: [RistrettoPoint; BITS],
    connector: Scalar,
    base_pubkeys: [RistrettoPoint; BITS],
    r_values: [[Scalar; 2]; BITS],
}

impl RangeProof {
    pub fn new<R>(
        rng: &mut R,
        value: u32,
        blinding_key: Scalar,
        blinding_base: &RistrettoPoint,
        key_image_base: &RistrettoPoint,
    ) -> RangeProof
    where
        R: RngCore + CryptoRng,
    {
        let mut base_pubkeys = [RistrettoPoint::default(); BITS];
        let mut mod_pubkeys = [RistrettoPoint::default(); BITS];
        let mut key_images = [RistrettoPoint::default(); BITS];
        let mut blinding_keys = [Scalar::default(); BITS];
        let mut total_other_blinding = Scalar::default();
        for i in 0..BITS {
            let bit_blinding = if i == BITS - 1 {
                blinding_key - total_other_blinding
            } else {
                let s = Scalar::random(rng);
                total_other_blinding += s;
                s
            };
            blinding_keys[i] = bit_blinding;
            key_images[i] = bit_blinding * key_image_base;
            let blinding_pub = bit_blinding * blinding_base;
            if value & (1 << i) == 0 {
                base_pubkeys[i] = blinding_pub;
                mod_pubkeys[i] =
                    blinding_pub - &Scalar::from(1u64 << i) * &RISTRETTO_BASEPOINT_TABLE;
            } else {
                base_pubkeys[i] =
                    blinding_pub + &Scalar::from(1u64 << i) * &RISTRETTO_BASEPOINT_TABLE;
                mod_pubkeys[i] = blinding_pub;
            }
        }
        let mut a_values = [Scalar::default(); BITS];
        let mut c2_values = [Scalar::default(); BITS];
        let mut r_values = [[Scalar::default(); 2]; BITS];
        let mut c1_hasher = Sha512::new();
        c1_hasher.input(RANGE_PROOF_MESSAGE);
        for i in 0..BITS {
            let a_val = Scalar::random(rng);
            a_values[i] = a_val;
            if value & (1 << i) == 0 {
                let c2_val = Scalar::from_hash(
                    Sha512::new()
                        .chain(RANGE_PROOF_MESSAGE)
                        .chain((a_val * blinding_base).compress().to_bytes())
                        .chain((a_val * key_image_base).compress().to_bytes()),
                );
                c2_values[i] = c2_val;
                let r2 = Scalar::random(rng);
                r_values[i][1] = r2;
                c1_hasher.input(
                    (r2 * blinding_base + c2_val * mod_pubkeys[i])
                        .compress()
                        .as_bytes(),
                );
                c1_hasher.input(
                    (r2 * key_image_base + c2_val * key_images[i])
                        .compress()
                        .as_bytes(),
                );
            } else {
                c1_hasher.input((a_val * blinding_base).compress().as_bytes());
                c1_hasher.input((a_val * key_image_base).compress().as_bytes());
            };
        }
        let c1 = Scalar::from_hash(c1_hasher);
        for i in 0..BITS {
            if value & (1 << i) == 0 {
                r_values[i][0] = a_values[i] - c1 * blinding_keys[i];
            } else {
                let r1 = Scalar::random(rng);
                r_values[i][0] = r1;
                let c2_val = Scalar::from_hash(
                    Sha512::new()
                        .chain(RANGE_PROOF_MESSAGE)
                        .chain(
                            (r1 * blinding_base + c1 * base_pubkeys[i])
                                .compress()
                                .to_bytes(),
                        )
                        .chain(
                            (r1 * key_image_base + c1 * key_images[i])
                                .compress()
                                .to_bytes(),
                        ),
                );
                c2_values[i] = c2_val;
                r_values[i][1] = a_values[i] - c2_val * blinding_keys[i];
            }
        }
        RangeProof {
            key_images,
            connector: c1,
            r_values,
            base_pubkeys,
        }
    }

    #[allow(clippy::needless_range_loop)] // zipping together everything would be a pain
    pub fn validate(
        &self,
        commitment: &RistrettoPoint,
        blinding_base: &RistrettoPoint,
        key_image_base: &RistrettoPoint,
    ) -> Result<(), ()> {
        if &self.base_pubkeys.iter().sum::<RistrettoPoint>() != commitment {
            return Err(());
        }
        let mut l2_values = [[RistrettoPoint::default(); 2]; BITS];
        for i in 0..BITS {
            let l11_val =
                self.r_values[i][0] * blinding_base + self.connector * self.base_pubkeys[i];
            let l12_val =
                self.r_values[i][0] * key_image_base + self.connector * self.key_images[i];
            let c2 = Scalar::from_hash(
                Sha512::new()
                    .chain(RANGE_PROOF_MESSAGE)
                    .chain(l11_val.compress().to_bytes())
                    .chain(l12_val.compress().to_bytes()),
            );
            let offset = Scalar::from(1u64 << i);
            let offset_pubkey = self.base_pubkeys[i] - &offset * &RISTRETTO_BASEPOINT_TABLE;
            l2_values[i] = [
                self.r_values[i][1] * blinding_base + c2 * offset_pubkey,
                self.r_values[i][1] * key_image_base + c2 * self.key_images[i],
            ];
        }
        let mut c1_hasher = Sha512::new();
        c1_hasher.input(RANGE_PROOF_MESSAGE);
        for row in &l2_values {
            for val in row {
                c1_hasher.input(val.compress().to_bytes());
            }
        }
        if Scalar::from_hash(c1_hasher) != self.connector {
            return Err(());
        }
        Ok(())
    }

    pub fn get_key_image(&self) -> RistrettoPoint {
        self.key_images.iter().sum()
    }
}
