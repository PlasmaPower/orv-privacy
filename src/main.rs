mod cross_base_proof;
mod range_proof;
mod secret_sharing;

use cross_base_proof::CrossBaseProof;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::Rng;
use range_proof::RangeProof;
use sha2::{Digest, Sha512};
use std::convert::TryInto;

const NUM_REP_SHARES: u16 = 10;
const NUM_REP_SHARES_NEEDED: u16 = NUM_REP_SHARES * 2 / 3;

fn main() {
    let mut rng = OsRng;
    let key_image_base = Sha512::new()
        .chain("commitment key image basepoint\0")
        .chain(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let key_image_base = RistrettoPoint::from_hash(key_image_base);
    let mut rep_keys = Vec::new();
    let mut rep_pubkeys = Vec::new();
    // this could be parallelized, and only needs to run e.g. daily
    for _ in 0..NUM_REP_SHARES {
        let secret = Scalar::random(&mut rng);
        let (verification, shares) = secret_sharing::generate(
            &mut rng,
            &key_image_base,
            secret,
            NUM_REP_SHARES_NEEDED,
            NUM_REP_SHARES,
        );
        // other reps can verify their shares
        assert_eq!(verification.get_needed(), NUM_REP_SHARES_NEEDED);
        for (i, &share) in shares.iter().enumerate() {
            assert!(verification
                .validate(&key_image_base, (i + 1).try_into().unwrap(), share)
                .is_ok());
        }
        // and if the rep goes offline, recombine their shares
        // after being released, each of these shares could also be verified by other reps
        let shares = &shares[1..=usize::from(NUM_REP_SHARES_NEEDED)];
        let share_nums: Vec<u16> = (2..(2 + NUM_REP_SHARES_NEEDED)).collect();
        assert_eq!(
            secret_sharing::combine_shares(&share_nums, shares),
            Ok(secret),
        );
        rep_pubkeys.push(verification.get_public().clone());
        rep_keys.push(secret);
    }
    // aggregate rep_pubkeys into blinding_base in a way safe against rogue key attacks
    // this is based on MuSig key aggregation - agg_mul_base is l
    let mut agg_mul_base = Sha512::new();
    for pubkey in &rep_pubkeys {
        agg_mul_base.input(pubkey.compress().as_bytes());
    }
    let agg_mul_base = agg_mul_base.result();
    let mut blinding_base = RistrettoPoint::default();
    for pubkey in &rep_pubkeys {
        let multiplier = Scalar::from_hash(
            Sha512::new()
                .chain(agg_mul_base.as_slice())
                .chain(pubkey.compress().as_bytes()),
        );
        blinding_base += pubkey * multiplier;
    }
    let blinding_key = Scalar::random(&mut rng);
    let balance1 = rng.gen::<u32>() / 10;
    let proof1 = RangeProof::new(
        &mut rng,
        balance1,
        blinding_key,
        &blinding_base,
        &key_image_base,
    );
    let commitment1 = &Scalar::from(u64::from(balance1)) * &RISTRETTO_BASEPOINT_TABLE
        + blinding_key * blinding_base;
    assert!(proof1
        .validate(&commitment1, &blinding_base, &key_image_base)
        .is_ok());
    let balance2 = rng.gen::<u32>() / 20;
    let proof2 = RangeProof::new(
        &mut rng,
        balance2,
        blinding_key,
        &blinding_base,
        &key_image_base,
    );
    let commitment2 = &Scalar::from(u64::from(balance2)) * &RISTRETTO_BASEPOINT_TABLE
        + blinding_key * blinding_base;
    assert!(proof2
        .validate(&commitment2, &blinding_base, &key_image_base)
        .is_ok());

    let total_weight = balance1 + balance2;
    let total_commitment = commitment1 + commitment2;
    let total_key_images = proof1.get_key_image() + proof2.get_key_image();
    let mut shared_key = RistrettoPoint::default();
    for (rep_key, rep_pubkey) in rep_keys.into_iter().zip(rep_pubkeys.into_iter()) {
        // if they are offline, this could be recovered via secert sharing as shown above
        let shared_key_part = rep_key * total_key_images;
        let equality_sig =
            CrossBaseProof::new(&mut rng, &key_image_base, &total_key_images, rep_key);
        // the public can validate shared_key_part, assuring them that decryption is correct
        assert!(equality_sig
            .validate(
                &key_image_base,
                &rep_pubkey,
                &total_key_images,
                &shared_key_part,
            )
            .is_ok());
        let key_multiplier = Scalar::from_hash(
            Sha512::new()
                .chain(agg_mul_base.as_slice())
                .chain(rep_pubkey.compress().as_bytes()),
        );
        shared_key += shared_key_part * key_multiplier;
    }
    // confirm that we've extracted the value
    // to actually get the value, we could use something like a rainbow table
    // E.g. precalculate all possible curve points, but only store curve points
    // whose first byte is 0. When doing lookup, add G until the curve point's
    // first byte is 0, then it's guaranteed to be in the table (which is small)
    let commitment_value = total_commitment - shared_key;
    assert_eq!(
        commitment_value,
        &Scalar::from(u64::from(total_weight)) * &RISTRETTO_BASEPOINT_TABLE,
    );
}
