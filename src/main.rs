mod cross_base_proof;
mod elgamal_proof;
mod secret_sharing;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use cross_base_proof::CrossBaseProof;
use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use elgamal_proof::ElgamalProof;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::convert::TryInto;

const NUM_REP_SHARES: u16 = 10;
const NUM_REP_SHARES_NEEDED: u16 = NUM_REP_SHARES * 2 / 3;
const DOMAIN_NAME: &[u8] = b"PlasmaPower/orv-privacy";

fn main() {
    println!("Generating shared rep key and secret sharing..");
    let mut rng = OsRng;
    let decryption_key_base = Sha512::new()
        .chain("commitment decryption key basepoint\0")
        .chain(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let decryption_key_base = RistrettoPoint::from_hash(decryption_key_base);
    let mut rep_keys = Vec::new();
    let mut rep_pubkeys = Vec::new();
    // this could be parallelized, and only needs to run e.g. daily
    for _ in 0..NUM_REP_SHARES {
        let secret = Scalar::random(&mut rng);
        let (verification, shares) = secret_sharing::generate(
            &mut rng,
            &decryption_key_base,
            secret,
            NUM_REP_SHARES_NEEDED,
            NUM_REP_SHARES,
        );
        // other reps can verify their shares
        // they also need to sign messages saying they've seen this verification
        // otherwise, a malicious dealer could give each a share to a different polynomial
        assert_eq!(verification.get_needed(), NUM_REP_SHARES_NEEDED);
        for (i, &share) in shares.iter().enumerate() {
            assert!(verification
                .validate(&decryption_key_base, (i + 1).try_into().unwrap(), share)
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

    println!("Done secret sharing, initializing bulletproofs..");
    let bulletproof_gens = BulletproofGens::new(32, 1);
    let pedersen_gens = PedersenGens {
        B: RISTRETTO_BASEPOINT_POINT,
        B_blinding: blinding_base,
    };
    println!("Done initializing bulletproofs, generating 2 commitments and proofs..");
    let blinding_key1 = Scalar::random(&mut rng);
    let decryption_key1 = blinding_key1 * decryption_key_base;
    let balance1 = u64::from(rng.gen::<u32>() / 10);
    let (range_proof1, commitment1) = RangeProof::prove_single(
        &bulletproof_gens,
        &pedersen_gens,
        &mut Transcript::new(DOMAIN_NAME),
        balance1,
        &blinding_key1,
        32,
    )
    .expect("Failed to prove range with bulletpoof");
    let elgamal_proof1 = ElgamalProof::new(
        &mut rng,
        blinding_key1,
        &blinding_base,
        balance1,
        &decryption_key_base,
    );

    let blinding_key2 = Scalar::random(&mut rng);
    let decryption_key2 = blinding_key2 * decryption_key_base;
    let balance2 = u64::from(rng.gen::<u32>() / 10);
    let (range_proof2, commitment2) = RangeProof::prove_single(
        &bulletproof_gens,
        &pedersen_gens,
        &mut Transcript::new(DOMAIN_NAME),
        balance2,
        &blinding_key2,
        32,
    )
    .expect("Failed to prove range with bulletpoof");
    let elgamal_proof2 = ElgamalProof::new(
        &mut rng,
        blinding_key2,
        &blinding_base,
        balance2,
        &decryption_key_base,
    );

    println!("Done generating commitments and proofs, verifying them..");
    assert_eq!(
        range_proof1.verify_single(
            &bulletproof_gens,
            &pedersen_gens,
            &mut Transcript::new(DOMAIN_NAME),
            &commitment1,
            32,
        ),
        Ok(())
    );
    assert_eq!(
        range_proof2.verify_single(
            &bulletproof_gens,
            &pedersen_gens,
            &mut Transcript::new(DOMAIN_NAME),
            &commitment2,
            32,
        ),
        Ok(())
    );
    let commitment1 = commitment1
        .decompress()
        .expect("Failed to decompress commitment");
    let commitment2 = commitment2
        .decompress()
        .expect("Failed to decompress commitment");
    assert!(elgamal_proof1
        .verify(
            &commitment1,
            &decryption_key1,
            &blinding_base,
            &decryption_key_base
        )
        .is_ok());
    assert!(elgamal_proof2
        .verify(
            &commitment2,
            &decryption_key2,
            &blinding_base,
            &decryption_key_base
        )
        .is_ok());

    println!("Done verifying proofs, decrypting total balance..");
    let total_weight = balance1 + balance2;
    let total_commitment = commitment1 + commitment2;
    let total_decryption_keys = decryption_key1 + decryption_key2;
    let mut shared_key = RistrettoPoint::default();
    for (rep_key, rep_pubkey) in rep_keys.into_iter().zip(rep_pubkeys.into_iter()) {
        // if they are offline, this could be recovered via secert sharing as shown above
        let shared_key_part = rep_key * total_decryption_keys;
        let equality_sig = CrossBaseProof::new(
            &mut rng,
            &decryption_key_base,
            &total_decryption_keys,
            rep_key,
        );
        // the public can validate shared_key_part, assuring them that decryption is correct
        assert!(equality_sig
            .validate(
                &decryption_key_base,
                &rep_pubkey,
                &total_decryption_keys,
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
        &Scalar::from(total_weight) * &RISTRETTO_BASEPOINT_TABLE,
    );
    println!("Successfully recovered total balance!");
}
