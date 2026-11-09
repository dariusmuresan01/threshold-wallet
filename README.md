# Threshold Wallet

A two-party threshold wallet for Bitcoin, built from scratch in Python.

Two devices each hold a share of the signing key and jointly produce an ordinary Bitcoin signature (Schnorr / BIP-340 and ECDSA) without the full key ever existing in one place. The signatures are checked by the standard verifier in [libsecp256k1](https://github.com/bitcoin-core/secp256k1), the same code Bitcoin Core uses.

> ⚠️ **Educational prototype.** This is a learning project, not a wallet. Do not use it with real funds. See [Limitations](#limitations).

---

## Why

A Bitcoin wallet is, at its core, one secret number: the private key. Keep a single copy and you have a single point of failure: lose it and the funds are gone, leak it and they are stolen. Keep several copies and every copy becomes another target.

Threshold signing offers a better trade-off. The key is split into shares, x = x₁ + x₂ (mod n), and each device holds one share. A single share looks like a uniformly random number and reveals nothing about the key. To sign, the devices run a short multi-party computation (MPC) protocol whose output is a perfectly normal signature, indistinguishable from one made by a regular wallet.

I am building this to understand, end to end, how the cryptography behind threshold custody actually works.

## How it works

```
              trusted dealer (setup only)
              splits the key and the randomness
                 x₁, k₁, …          x₂, k₂, …
                    │                  │
                    ▼                  ▼
              ┌──────────┐  MPC   ┌──────────┐
              │ Device A │ ◄────► │ Device B │
              └────┬─────┘        └────┬─────┘
                   └───────┬───────────┘
                           ▼
              ordinary 64-byte signature
                           ▼
              libsecp256k1 verifier → True
```

- **Schnorr (BIP-340)** is linear: s = k + e·d. Each device computes sᵢ = kᵢ + e·dᵢ on its own shares, the nonce point is assembled from public pieces (R = k₁·G + k₂·G), and the shares of s simply add up. The only subtleties are BIP-340's x-only keys and even-y rule, which have to be enforced on shares.
- **ECDSA** is not linear: s = k⁻¹·(H(m) + r·x) needs an inversion and a product of two secrets. That is where real MPC comes in: arithmetic secret sharing in the style of **BeDOZa**, with Beaver triples for multiplication and masking for inversion.
- A **trusted dealer** provides the initial shares and the correlated randomness. Security is **passive** (semi-honest): both devices follow the protocol but may try to learn more than they should.

## Status

| | Component | |
|---|---|---|
| ✅ | Project setup (Python 3.12, `coincurve` / libsecp256k1) | |
| ✅ | Single-signer **Schnorr (BIP-340)**, implemented by hand and accepted by the libsecp256k1 verifier | [`src/schnorr.py`](src/schnorr.py) |
| ✅ | Single-signer **ECDSA** with low-s normalisation and strict DER encoding/decoding (BIP-66), accepted by the libsecp256k1 verifier | [`src/ecdsa.py`](src/ecdsa.py) |
| ⏳ | Nonce-reuse attack demo (why a repeated nonce leaks the key) | next |
| ⏳ | Additive secret sharing and passive **BeDOZa** (Beaver triples, secure inversion) | planned |
| ⏳ | **Two-party threshold Schnorr** | planned |
| ⏳ | **Two-party threshold ECDSA** | planned |
| ⏳ | Fixed test vectors (incl. official BIP-340 vectors) and malformed-share tests | planned |
| 💡 | Cost comparison: Schnorr vs ECDSA (rounds, triples, opened values, time) | stretch goal |

## Getting started

Requires **Python 3.12**. (Very new Python versions may not have prebuilt `coincurve` wheels yet and will try to compile from source.)

```bash
git clone https://github.com/dariusmuresan01/threshold-wallet.git
cd threshold-wallet
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/schnorr.py
python src/ecdsa.py
```

Each script runs its own test suite and ends with:

```
All tests have passed!
```

## What `src/schnorr.py` does

A reference BIP-340 signer written from first principles, using libsecp256k1 only for elliptic-curve operations:

- conversions between scalars and 32-byte big-endian encodings;
- the BIP-340 tagged hash, `SHA256(SHA256(tag) || SHA256(tag) || data)`;
- x-only keys and the even-y rule (negating d or k when the point has odd y);
- signing: `e = H_challenge(x(R) || x(P) || m)`, `s = k + e·d mod n`, signature `x(R) || s`.

Its built-in tests check that 50 signatures with fresh random keys all verify, that flipping a single bit in the message, in r or in s makes verification fail, that a signature does not verify under someone else's key, and that signing the same message twice gives two different valid signatures.

This single-signer version is the baseline the threshold protocol will be checked against.

## What `src/ecdsa.py` does

A reference ECDSA signer, reusing the helpers from `schnorr.py`:

- signing: `r = x(k·G) mod n`, `s = k⁻¹·(z + r·d) mod n`, retrying on the (astronomically unlikely) zero cases;
- **low-s** normalisation (`s ≤ n/2`), which libsecp256k1 enforces to rule out malleable signatures;
- strict **DER** encoding and decoding of `(r, s)`, as required by BIP-66.

Its tests check that 50 signatures verify under libsecp256k1 with low `s`, that the "high-s" twin `(r, n − s)` is rejected, that a modified message, a modified `s` or a different key all fail, and that a structurally broken DER blob is refused outright.

ECDSA is the hard case for threshold signing: the inverse `k⁻¹` and the product `k⁻¹·d` cannot be computed share by share, which is exactly what the MPC layer will have to solve.

## Project layout

```
threshold-wallet/
├── src/
│   ├── schnorr.py        single-signer BIP-340 reference
│   └── ecdsa.py          single-signer ECDSA reference (low-s, DER)
├── tests/                test suite (coming)
├── requirements.txt
└── README.md
```

## Limitations

This prototype deliberately leaves out what a production threshold wallet needs:

- **passive security only**: a device that deviates from the protocol is not detected;
- **trusted dealer**: the setup party knows everything by construction;
- **no side-channel protection** in the Python code;
- **no handling of aborts** or of persistent nonce state across sessions;
- **not post-quantum**: like all elliptic-curve signatures, it would fall to a large quantum computer.

## References

- [BIP-340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-66: Strict DER signatures](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)
- A. Dalskov, C. Orlandi, M. Keller, K. Shrishak, H. Shulman, *Securing DNSSEC Keys via Threshold ECDSA from Generic MPC* ([ePrint 2019/889](https://eprint.iacr.org/2019/889))
- R. Bendlin, I. Damgård, C. Orlandi, S. Zakarias, *Semi-Homomorphic Encryption and Multiparty Computation* ([ePrint 2010/514](https://eprint.iacr.org/2010/514))
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1) and its Python binding [coincurve](https://github.com/ofek/coincurve)
