# orv-privacy

An example cryptosystem to add amount privacy while being able to reveal sums of commitments (representative weights).

## Algorithm description

Each representative generates a key relative to basepoint `H`, and uses a verifiable secret sharing algorithm (in this codebase Feldman's scheme) to ensure that the key can be recovered even if they disappear.
This verifiable secret sharing algorithm must also verify that the rep knows the private key `k` for which their key `K = kH`, as otherwise the commitments might be malleable.

The basepoint for the commitment blinding key `P` is created by summing `Kn * Hs(H(K1 || K2 || ... || Kn) || Kn)` where `H(x)` is a cryptographic hash function and `Hs(x) = H(x) % l`, as seen in MuSig to prevent rogue key attacks.

Balance commitments are generated normally, and signing as them to prove they're a commitment can be done normally (though it could be modified to make it perfectly binding).
The range proofs are also normal, in this repository bulletproofs.
I'll be referring to the variables of the commitments as `b*G + x*P` where `b` is the balance, `G` is the normal basepoint, and `x` is the blinding key (`P` was defined earlier as the aggregated rep keys).

Included with the commitment, there's also a decryption key and a proof that it's correct.
The decryption key `I = x*H` turns the Pedersen commitment into an ElGamal ciphertext.
To prove the validity of this, I use the proof from https://eprint.iacr.org/2019/319.pdf figure 3.
In essence, this first signs as the key image over H, then reuses the `s` value from that and adds it to effectively a signature as the balance over `G`.
The verifier can then verify that "sum signature" against the commitment itself.
I do make one modification from the algorithm described in the paper.
Instead of sending both `A` and `B`, I only send `e`.
The verifier reconstructs `A` and `B` from the `e` value, then checks if `e == H(A, B)`.

All representatives will then total the commitments and decryption keys for each representative (not just for themselves).
A scheme like epoch blocks would be needed to get representatives to agree on a point in time to calculate this.
Once that's done, for each total decryption key `I`, each representative releases `D = kI` where `k` is their key.
To prove that this released `S` value is correct, the representative generates a random scalar `a`, then computes `c = Hs(a*H || a*I)` and `s = a + c*k` and releases both.
This can be verified by validating `c = Hs((s*H - c*K) || (s*I - c*D))`.
This is very similar to the linkable borromean ring signatures mentioned before.
Any representative that does not release `D` or for which verification fails will have their key publicly recovered by the others using the secret sharing scheme described at the start.

Finally, `b*G = c - D1 - D2 - ... - Dn` is computed for each total commitment.
This works because if we call the aggregated rep secret keys `p`, `c - pI = (b*G + x*P) - p*x*H = b*G + x*p*H - p*x*H = b*G`.
`p` is never computed, but its components multiplied by `I` are the decryption shares `D1 + D2 + ... + Dn = pI`.
To recover `b` itself, the total weight, a precomputed lookup table can be utilized.
To reduce the size of the lookup table, it can be limited to points which start with the `00` byte (and this byte doesn't need to be stored).
Then, `G` is added to `b*G` until it starts with a `00` byte too (and a count is kept of how many times this was done).
That modified `b*G` will be in the lookup table, and the scalar in the lookup table will have the count subtracted from it to recover `b`, the total weight.
