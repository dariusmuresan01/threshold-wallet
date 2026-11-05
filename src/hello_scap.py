from coincurve import PrivateKey

sk = PrivateKey()

sig = sk.sign(b"Hello")

print(sk.public_key.verify(sig, b"Hello"))