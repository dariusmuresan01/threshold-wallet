# 64-byte Schnorr signatures over the elliptic curve secp256k1

import hashlib
import secrets

from coincurve import PublicKey, PublicKeyXOnly

# The order of the group over the elliptic curve secp256k1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# bytes32(x) from BIP-340: x as exactly 32 bytes, big-endian
# (a signature is x(R) || bytes32(s) = 32 + 32 = 64 bytes)
def int_to_bytes32(x: int) -> bytes:
    return x.to_bytes(32, "big")

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

# Tagged hash from BIP-340: SHA256(SHA256(tag) || SHA256(tag) || data)
# The tag separates domains: hashes for different purposes never collide.
# With tag "BIP0340/challenge" it gives the challenge e of the signature.
def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    result = hashlib.sha256(tag_hash + tag_hash + data).digest()
    return result

# Is the y coordinate of P even? (compressed prefix 0x02 = even, 0x03 = odd)
# BIP-340 always uses the point with even y.
def has_even_y(P: PublicKey) -> bool:
    return P.format(compressed=True)[0] == 0x02

# x(P) from BIP-340: only the x coordinate, 32 bytes (the x-only key).
def x_only(P: PublicKey) -> bytes:
    return P.format(compressed=True)[1:]

# k·G: the point for scalar k (the library does the curve math).
def point_from_scalar(k: int) -> PublicKey:
    return PublicKey.from_secret(int_to_bytes32(k))

# BIP-340 Schnorr signature of msg with private key d (reference version).
def schnorr_sign(d: int, msg: bytes) -> bytes:
    P = point_from_scalar(d)
    if not has_even_y(P):
        d = N - d
    k = secrets.randbelow(N - 1) + 1
    R = point_from_scalar(k)
    if not has_even_y(R):
        k = N - k
    e = bytes_to_int(tagged_hash("BIP0340/challenge", x_only(R) + x_only(P) + msg)) % N
    s = (k + e * d) % N
    return x_only(R) + int_to_bytes32(s)

# Test helper: copy of b with the lowest bit of byte i flipped.
def flip_byte(b: bytes, i: int) -> bytes:
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]

if __name__ == "__main__":
    for x in [0, 1, 12345, N-1]:
        assert bytes_to_int(int_to_bytes32(x)) == x
    print(int_to_bytes32(1).hex())
    try:
        int_to_bytes32(-1)
        assert False, "Error: negative number"
    except OverflowError:
        print("First error gathered correctly!")
    try:
        int_to_bytes32(2**256)
        assert False, "Error: the number exceeds the limit"
    except OverflowError:
        print("Second error gathered correctly!")
    assert tagged_hash("BIP0340/challenge", b"").hex() == "c216d352f5818b7b4beacd4ae0a26fe888080823d2a598856661bcd54f1b3713"
    assert tagged_hash("BIP0340/challenge", b"abc").hex() == "770a5b7e7c304bbcc3ea107343ff951dd404312ef418db0c3b94e2ebfbb50087"
    G = PublicKey.from_secret(int_to_bytes32(1))
    assert x_only(G).hex() == "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert has_even_y(G)
    for d in [1, 2, 3, 12345]:
        P = PublicKey.from_secret(int_to_bytes32(d))
        Q = PublicKey.from_secret(int_to_bytes32(N - d))
        assert x_only(P) == x_only(Q)
        assert has_even_y(P) != has_even_y(Q)
        x, y = P.point()
        assert has_even_y(P) == (y % 2 == 0)
    msg = hashlib.sha256(b"Hello").digest()
    for _ in range(50):
        d = secrets.randbelow(N - 1) + 1
        sig = schnorr_sign(d, msg)
        assert len(sig) == 64
        xP = x_only(point_from_scalar(d))
        assert PublicKeyXOnly(xP).verify(sig, msg)
    assert not PublicKeyXOnly(xP).verify(sig, flip_byte(msg, 0))
    assert not PublicKeyXOnly(xP).verify(flip_byte(sig, 63), msg)
    assert not PublicKeyXOnly(xP).verify(flip_byte(sig, 0), msg)
    other_d = secrets.randbelow(N) + 1
    other_xP = x_only(point_from_scalar(other_d))
    assert not PublicKeyXOnly(other_xP).verify(sig, msg)
    sig1 = schnorr_sign(d, msg)
    sig2 = schnorr_sign(d, msg)
    assert sig1 != sig2
    assert PublicKeyXOnly(xP).verify(sig1, msg)
    assert PublicKeyXOnly(xP).verify(sig2, msg)
    print("All tests have passed!")