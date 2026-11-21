# Two-party threshold BIP-340 Schnorr on top of passive BeDOZa (simulation)

import secrets

from coincurve import PublicKeyXOnly, PublicKey

from schnorr import (
    N, int_to_bytes32, bytes_to_int, tagged_hash, x_only, has_even_y, point_from_scalar, schnorr_sign
)

from bedoza import (
    Shared, open_shared, add, mul_const, lift, random_nonzero_shared, share
)

# Negate a shared value: each party replaces its share by N − share
def negate(x: Shared) -> Shared:
    return mul_const(x, N - 1)

# Key setup (run once): the dealer shares a random key d, the parties lift it to P and both negate their shares if P has odd y (BIP-340)
def keygen() -> tuple[Shared, bytes]:
    sd = random_nonzero_shared()
    P = lift(sd)
    if not has_even_y(P):
        sd = negate(sd)
    return sd, x_only(P)

# Round 1 (every signature): each party picks its own nonce share, the parties lift to R and both negate if R has odd y
def nonce_round() -> tuple[Shared, bytes]:
    k_a = secrets.randbelow(N - 1) + 1
    k_b = secrets.randbelow(N - 1) + 1
    sk = (k_a, k_b)
    R = lift(sk)
    if not has_even_y(R):
        sk = negate(sk)
    return sk, x_only(R)

# BIP-340 challenge e = H(x(R) ‖ x(P) ‖ m) mod N, computed by each party from public values
def challenge(x_R: bytes, x_P: bytes, msg: bytes) -> int:
    return bytes_to_int(tagged_hash("BIP0340/challenge", (x_R + x_P + msg))) % N

# Sign msg with the shared key: round 1 gives R, round 2 opens s = k + e*d
def threshold_sign(sd: Shared, x_P: bytes, msg: bytes) -> bytes:
    sk, x_R = nonce_round()
    e = challenge(x_R, x_P, msg)
    ss = add(sk, mul_const(sd, e))
    s = open_shared(ss)
    return x_R + int_to_bytes32(s)

# (BAD, demo only) A reuses its nonce share k_a; returns the signature and A’s partial response s_A, which B receives
def bad_threshold_sign(sd: Shared, x_P: bytes, msg: bytes, k_a: int) -> tuple[bytes, int]:
    k_b = secrets.randbelow(N - 1) + 1
    sk = (k_a, k_b)
    R = lift(sk)
    if not has_even_y(R):
        sk = negate(sk)
    x_R = x_only(R)
    e = challenge(x_R, x_P, msg)
    ss = add(sk, mul_const(sd, e))
    s = open_shared(ss)
    sig = x_R + int_to_bytes32(s)
    return sig, ss[0]

# Attack by B: recover A’s key share from two signatures where A reused its nonce share (tries both parity cases, checks against P_A)
def recover_share(sig1: bytes, msg1: bytes, s_a1: int, sig2: bytes, msg2: bytes, s_a2: int, x_P: bytes, P_A: PublicKey) -> int:
    e1 = challenge(sig1[:32], x_P, msg1)
    e2 = challenge(sig2[:32], x_P, msg2)
    cand_same = (pow((e1 - e2) % N, -1, N) * (s_a1 - s_a2)) % N
    cand_dif = (pow((e1 + e2) % N, -1, N) * (s_a1 + s_a2)) % N
    for cand in (cand_same, cand_dif):
        if point_from_scalar(cand).format() == P_A.format():
            return cand
    raise ValueError("signatures do not come from a reused nonce share")

if __name__ == "__main__":
    x = secrets.randbelow(N - 1)
    sx = share(x)
    assert open_shared(negate(sx)) == (N - x) % N
    print("Negate function works!")
    for _ in range(50):
        sd, x_P = keygen()
        d = open_shared(sd)
        Q = point_from_scalar(d)
        assert has_even_y(Q)
        assert x_only(Q) == x_P
    print("Keygen function works!")
    for _ in range(50):
        sk, x_R = nonce_round()
        k = open_shared(sk)
        Q = point_from_scalar(k)
        assert has_even_y(Q)
        assert x_only(Q) == x_R
    assert nonce_round() != nonce_round()
    print("Nonce Round function works!")
    for _ in range(50):
        sd, x_P = keygen()
        msg = secrets.token_bytes(32)
        sig = threshold_sign(sd, x_P, msg)
        assert len(sig) == 64
        assert PublicKeyXOnly(x_P).verify(sig, msg)
        assert not PublicKeyXOnly(x_P).verify(sig, message=secrets.token_bytes(32))
    print("Threshold sign function works!")
    for _ in range(50):
        sd, x_P = keygen()
        msg = secrets.token_bytes(32)
        sig1 = schnorr_sign(open_shared(sd), msg)
        assert PublicKeyXOnly(x_P).verify(sig1, msg)
        sig = threshold_sign(sd, x_P, msg)
        s = bytes_to_int(sig[32:])
        bad_sig = sig[:32] + int_to_bytes32((s + 1) % N)
        assert not PublicKeyXOnly(x_P).verify(bad_sig, msg)
    print("A corrupted partial share makes the signature invalid")
    k_a = secrets.randbelow(N - 1) + 1
    sd, x_P = keygen()
    for _ in range(50):
        msg = secrets.token_bytes(32)
        sig, s_a = bad_threshold_sign(sd, x_P, msg, k_a)
        assert PublicKeyXOnly(x_P).verify(sig, msg)
    print("A reused nonce share still gives valid signatures: invisible from outside")
    sd, x_P = keygen()
    k_a = secrets.randbelow(N - 1) + 1
    P_A = point_from_scalar(sd[0])  # A published this point at key setup, so B knows it
    for _ in range(50):
        msg1 = secrets.token_bytes(32)
        msg2 = secrets.token_bytes(32)
        sig1, s_a1 = bad_threshold_sign(sd, x_P, msg1, k_a)
        sig2, s_a2 = bad_threshold_sign(sd, x_P, msg2, k_a)
        d_a = recover_share(sig1, msg1, s_a1, sig2, msg2, s_a2, x_P, P_A)
        assert d_a == sd[0]
        d = (d_a + sd[1]) % N
        msg3 = secrets.token_bytes(32)
        forged = schnorr_sign(d, msg3)
        assert PublicKeyXOnly(x_P).verify(forged, msg3)
    print("B recovered A's share and the full key from a reused nonce share")
    msg1 = secrets.token_bytes(32)
    msg2 = secrets.token_bytes(32)
    sig1, s_a1 = bad_threshold_sign(sd, x_P, msg1, secrets.randbelow(N - 1) + 1)
    sig2, s_a2 = bad_threshold_sign(sd, x_P, msg2, secrets.randbelow(N - 1) + 1)
    try:
        recover_share(sig1, msg1, s_a1, sig2, msg2, s_a2, x_P, P_A)
        assert False, "different nonce shares must not reveal A's share"
    except ValueError:
        print("Fresh nonce shares: the attack finds nothing")
    print("All tests have passed!")