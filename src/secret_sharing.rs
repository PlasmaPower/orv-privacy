use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use std::collections::HashSet;
use std::convert::TryInto;
use std::ops::MulAssign;

pub struct Verification(Vec<RistrettoPoint>);

pub fn generate<R>(
    rng: &mut R,
    basepoint: &RistrettoPoint,
    secret: Scalar,
    needed: u16,
    num_shares: u16,
) -> (Verification, Vec<Scalar>)
where
    R: RngCore + CryptoRng,
{
    assert!(needed > 0);
    assert!(num_shares > 0);
    assert!(num_shares >= needed);
    let mut coeffs = Vec::with_capacity(usize::from(needed));
    coeffs.push(secret);
    for _ in 1..needed {
        coeffs.push(Scalar::random(rng));
    }
    let verification = coeffs.iter().map(|c| c * basepoint).collect();
    let mut shares = Vec::with_capacity(usize::from(num_shares));
    for x in 1..=num_shares {
        let x_scalar = Scalar::from(u64::from(x));
        let mut curr_x_pow = Scalar::one();
        let mut total = Scalar::zero();
        for coeff in &coeffs {
            total += coeff * curr_x_pow;
            curr_x_pow *= x_scalar;
        }
        shares.push(total);
    }
    (Verification(verification), shares)
}

impl Verification {
    pub fn get_public(&self) -> &RistrettoPoint {
        &self.0[0]
    }

    pub fn get_needed(&self) -> u16 {
        self.0.len().try_into().unwrap()
    }

    pub fn validate(
        &self,
        basepoint: &RistrettoPoint,
        share_num: u16,
        share: Scalar,
    ) -> Result<(), ()> {
        let x_scalar = Scalar::from(u64::from(share_num));
        let mut curr_x_pow = Scalar::one();
        let mut total = RistrettoPoint::default();
        for coeff in &self.0 {
            total += coeff * curr_x_pow;
            curr_x_pow *= x_scalar;
        }
        if share * basepoint == total {
            Ok(())
        } else {
            Err(())
        }
    }
}

// currently unused, but would work
impl MulAssign<Scalar> for Verification {
    fn mul_assign(&mut self, other: Scalar) {
        for coeff in self.0.iter_mut() {
            *coeff *= other;
        }
    }
}

pub fn combine_shares(share_nums: &[u16], shares: &[Scalar]) -> Result<Scalar, ()> {
    if shares.is_empty() || share_nums.len() != shares.len() {
        return Err(());
    }
    let share_nums_set: HashSet<u16> = share_nums.iter().cloned().collect();
    if share_nums_set.len() != shares.len() || share_nums_set.contains(&0) {
        return Err(());
    }
    let mut total = Scalar::zero();
    for (&share_num_int, share) in share_nums.iter().zip(shares.iter()) {
        let share_num = Scalar::from(u64::from(share_num_int));
        // based on Lagrange basis polynomials, but optimized for y=0
        let mut processed_part = *share;
        for &other_share_num_int in share_nums {
            if share_num_int == other_share_num_int {
                continue;
            }
            let other_share_num = Scalar::from(u64::from(other_share_num_int));
            let denom = other_share_num - share_num;
            processed_part *= other_share_num * denom.invert();
        }
        total += processed_part;
    }
    Ok(total)
}
