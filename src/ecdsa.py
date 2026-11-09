# ECDSA signatures over secp256k1, reference version, DER-encoded as in BIP-66

import hashlib
import secrets

from schnorr import (
    N, 
    int_to_bytes32, 
    bytes_to_int, 
    point_from_scalar, 
    flip_byte,
)

# DER INTEGER: 02 ‖ length ‖ minimal big-endian bytes, with a 00 prefix if the top bit is set
def der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if b[0] >= 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b

# DER signature (BIP-66): 30 ‖ length ‖ INTEGER(r) ‖ INTEGER(s)
def der_encode(r: int, s: int) -> bytes:
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body

# Inverse of der_encode: read (r, s) back from DER bytes
def der_decode(sig: bytes) -> tuple[int, int]:
    r_len = sig[3]
    r = bytes_to_int(sig[4:4 + r_len])
    s_len = sig[5 + r_len]
    s = bytes_to_int(sig[6 + r_len:6 + r_len + s_len])
    return r, s

# ECDSA signature of a 32-byte hash msg with private key d: low-s, DER-encoded
def ecdsa_sign(d: int, msg: bytes) -> bytes:
    z = bytes_to_int(msg) % N
    while True:
        k = secrets.randbelow(N - 1) + 1
        R = point_from_scalar(k)
        r = R.point()[0] % N
        if r == 0:
            continue
        k_inv = pow(k, -1, N)
        s = (k_inv * (z + r * d)) % N
        if s == 0:
            continue
        if s > N // 2:
            s = N - s
        return der_encode(r, s)

if __name__ == "__main__":
    assert bytes_to_int(int_to_bytes32(12345)) == 12345
    assert point_from_scalar(1).point()[0] == 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    assert der_encode(0x0123, 0x8000).hex() == "3009020201230203008000"
    assert der_encode(0x7F, 0x80).hex() == "300702017f02020080"
    msg = hashlib.sha256(b"Hello").digest()
    assert der_decode(der_encode(0x0123, 0x8000)) == (0x0123, 0x8000)
    for _ in range(50):
        d = secrets.randbelow(N - 1) + 1
        sig = ecdsa_sign(d, msg)
        assert sig[0] == 0x30
        assert len(sig) <= 72
        P = point_from_scalar(d)
        assert P.verify(sig, msg, hasher=None)
        r, s = der_decode(sig)
        assert s <= N // 2
    assert not P.verify(sig, flip_byte(msg, 0), hasher=None)
    other_P = point_from_scalar(secrets.randbelow(N - 1) + 1)
    assert not P.verify(der_encode(r, N - s), msg, hasher=None)
    assert not other_P.verify(sig, msg, hasher=None)
    assert not P.verify(flip_byte(sig, len(sig) - 1), msg, hasher=None)
    try:
        P.verify(flip_byte(sig, 0), msg, hasher=None)
        assert False, "Corrupted DER should raise ValueError."
    except ValueError:
        print("Error gathered correctly!")
    print("All tests have passed!")