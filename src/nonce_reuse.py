# DEMO ONLY: nonce-reuse attacks on Schnorr and ECDSA. Never sign with a caller-chosen nonce.

import hashlib
import secrets

from coincurve import PublicKey, PublicKeyXOnly
from schnorr import (
    point_from_scalar,
    has_even_y,
    N,
    bytes_to_int,
    tagged_hash,
    x_only,
    int_to_bytes32,
    schnorr_sign,
)
from ecdsa import der_encode, der_decode, ecdsa_sign

# Schnorr (BIP-340) signing with a caller-supplied nonce k. INSECURE by design.
def bad_schnorr_sign(d: int, msg: bytes, k: int) -> bytes:
    P = point_from_scalar(d)
    if not has_even_y(P):
        d = N - d
    R = point_from_scalar(k)
    if not has_even_y(R):
        k = N - k
    e = bytes_to_int(tagged_hash("BIP0340/challenge", x_only(R) + x_only(P) + msg)) % N
    s = (k + e * d) % N
    return x_only(R) + int_to_bytes32(s)

# Attacker: recover the private key from two BIP-340 signatures that reuse the same nonce
def recover_schnorr_key(sig1: bytes, msg1: bytes, sig2: bytes, msg2: bytes, x_P: bytes) -> int:
    r = sig1[:32]
    if sig2[:32] != r:
        raise ValueError("signatures do not share the same R")
    s1 = bytes_to_int(sig1[32:])
    s2 = bytes_to_int(sig2[32:])
    e1 = bytes_to_int(tagged_hash("BIP0340/challenge", r + x_P + msg1)) % N
    e2 = bytes_to_int(tagged_hash("BIP0340/challenge", r + x_P + msg2)) % N
    return ((s1 - s2) * pow((e1 - e2) % N, -1, N)) % N

# ECDSA signing with a caller-supplied nonce k
def bad_ecdsa_sign(d: int, msg: bytes, k: int) -> bytes:
    z = bytes_to_int(msg) % N
    R = point_from_scalar(k)
    r = R.point()[0] % N
    if r == 0:
        raise ValueError
    k_inv = pow(k, -1, N)
    s = (k_inv * (z + r * d)) % N
    if s == 0:
        raise ValueError
    if s > N // 2:
        s = N - s
    return der_encode(r, s)

# Attacker: recover the private key from two ECDSA signatures that reuse the same nonce
def recover_ecdsa_key(sig1: bytes, msg1: bytes, sig2: bytes, msg2: bytes, P: PublicKey) -> int:
    r1, s1 = der_decode(sig1)
    r2, s2 = der_decode(sig2)
    if r1 != r2:
        raise ValueError("signatures do not share the same r")
    z1 = bytes_to_int(msg1) % N
    z2 = bytes_to_int(msg2) % N
    r_inv = pow(r1, -1, N)
    k_a = (z1 - z2) * pow((s1 - s2) % N, -1, N) % N
    k_b = (z1 - z2) * pow((s1 + s2) % N, -1, N) % N
    for k in (k_a, k_b):
        d = ((s1 * k - z1) * r_inv) % N
        if point_from_scalar(d).format() == P.format():
            return d
    raise ValueError("no candidate key matches the public key")

if __name__ == "__main__":
    msg1 = hashlib.sha256(b"Pay Alice 1 BTC").digest()
    msg2 = hashlib.sha256(b"Pay Bob 1 BTC").digest()
    msg3 = hashlib.sha256(b"Pay Mallory 100 BTC").digest()
    for _ in range(50):
        d = secrets.randbelow(N - 1) + 1
        x_P = x_only(point_from_scalar(d))
        k = secrets.randbelow(N - 1) + 1
        sig1 = bad_schnorr_sign(d, msg1, k)
        sig2 = bad_schnorr_sign(d, msg2, k)
        assert PublicKeyXOnly(x_P).verify(sig1, msg1)
        assert PublicKeyXOnly(x_P).verify(sig2, msg2)
        assert sig1[:32] == sig2[:32]
        d_rec = recover_schnorr_key(sig1, msg1, sig2, msg2, x_P)
        assert d_rec == d or d_rec == N - d
        assert x_only(point_from_scalar(d_rec)) == x_P
        forged = schnorr_sign(d_rec, msg3)
        assert PublicKeyXOnly(x_P).verify(forged, msg3)
    print("Schnorr: key recovered and a new signature forged in 50/50 runs.")
    good1 = schnorr_sign(d, msg1)
    good2 = schnorr_sign(d, msg2)
    try:
        recover_schnorr_key(good1, msg1, good2, msg2, x_P)
        assert False, "the Schnorr attack must refuse signatures with different R"
    except ValueError:
        print("Schnorr: correct signatures have different R, the attack is refused.")
    for _ in range(50):
        d = secrets.randbelow(N - 1) + 1
        P = point_from_scalar(d)
        k = secrets.randbelow(N - 1) + 1
        esig1 = bad_ecdsa_sign(d, msg1, k)
        esig2 = bad_ecdsa_sign(d, msg2, k)
        assert P.verify(esig1, msg1, hasher=None)
        assert P.verify(esig2, msg2, hasher=None)
        assert der_decode(esig1)[0] == der_decode(esig2)[0]
        d_rec = recover_ecdsa_key(esig1, msg1, esig2, msg2, P)
        assert d_rec == d
        forged = ecdsa_sign(d_rec, msg3)
        assert P.verify(forged, msg3, hasher=None)
    print("ECDSA: key recovered and a new signature forged in 50/50 runs.")

    # Correct ECDSA signatures (fresh nonces) cannot be attacked
    good1 = ecdsa_sign(d, msg1)
    good2 = ecdsa_sign(d, msg2)
    try:
        recover_ecdsa_key(good1, msg1, good2, msg2, P)
        assert False, "the ECDSA attack must refuse signatures with different r"
    except ValueError:
        print("ECDSA: correct signatures have different r, the attack is refused.")

    print("All tests have passed!")