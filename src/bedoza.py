# Passive two-party BeDOZa-style arithmetic over Z_N with a trusted dealer (simulation)

import secrets

from coincurve import PublicKey
from schnorr import N, point_from_scalar

# A shared value [x]: (share of party A, share of party B), with x = x_A + x_B mod N
Shared = tuple[int, int]

Triple = tuple[Shared, Shared, Shared]

# Put x in a box: A's share is uniformly random, B's share is the difference
def share(x: int) -> Shared:
    x_a = secrets.randbelow(N)
    x_b = (x - x_a) % N
    return x_a, x_b

# Open a box: both parties publish their shares and add them
def open_shared(x: Shared) -> int:
    return (x[0] + x[1]) % N

def add(x: Shared, y: Shared) -> Shared:
    return (x[0] + y[0]) % N, (x[1] + y[1]) % N

def sub(x: Shared, y: Shared) -> Shared:
    return (x[0] - y[0]) % N, (x[1] - y[1]) % N

def mul_const(x: Shared, c: int) -> Shared:
    return (x[0] * c) % N, (x[1] * c) % N

def add_const(x: Shared, c: int) -> Shared:
    return(x[0] + c) % N, x[1]

# ---------- Trusted dealer (preprocessing) ----------
# The dealer sees the values in clear, hands out only the shares, then forgets everything
def random_shared() -> Shared:
    return share(secrets.randbelow(N))

def random_nonzero_shared() -> Shared:
    return share(secrets.randbelow(N - 1) + 1)

# Beaver triple ([a], [b], [c]) with c = a*b: used to multiply two shared values
def beaver_triple() -> Triple:
    a = secrets.randbelow(N)
    b = secrets.randbelow(N)
    c = (a * b) % N
    return share(a), share(b), share(c)

# ---------- Interactive operations ----------
# Beaver multiplication: [x*y] from [x], [y] and one fresh triple (opens eps = x - a, delta = y - b)
def multiply(x: Shared, y: Shared, triple: Triple) -> Shared:
    ta, tb, tc = triple
    epsilon = open_shared(sub(x, ta))
    delta = open_shared(sub(y, tb))
    z = add(tc, mul_const(tb, epsilon))
    z = add(z, mul_const(ta, delta))
    z = add_const(z, (epsilon * delta) % N)
    return z

# Masked inversion: [k^-1] from [k], a fresh nonzero mask [b] and one triple (opens c = k*b)
def invert(k: Shared, mask: Shared, triple: Triple) -> Shared:
    c_shared = multiply(k, mask, triple)
    c_open = open_shared(c_shared)
    if c_open == 0:
        raise ValueError("opened k*b is zero: restart with a fresh k or mask")
    c_inv = pow(c_open, -1, N)
    return mul_const(mask, c_inv)

# Lifting: the public point x*G from [x] without opening it (each party publishes x_i*G)
def lift(x: Shared) -> PublicKey:
    X_a = point_from_scalar(x[0])
    X_b = point_from_scalar(x[1])
    return PublicKey.combine_keys([X_a, X_b])

if __name__ == "__main__":
    for i in [0, 1, 12345, N - 1]:
        assert open_shared(share(i)) == i
    assert share(5) != share(5)
    for _ in range(50):
        x = secrets.randbelow(N)
        y = secrets.randbelow(N)
        c = secrets.randbelow(N)
        sx, sy = share(x), share(y)
        assert open_shared(add(sx, sy)) == (x + y) % N
        assert open_shared(sub(sx, sy)) == (x - y) % N
        assert open_shared(mul_const(sx, c)) == (x * c) % N
        assert open_shared(add_const(sx, c)) == (x + c) % N
        assert open_shared(add_const(sub(mul_const(sx, 2), sy), 1)) == (2 * x - y + 1) % N
    for _ in range(50):
        ta, tb, tc = beaver_triple()
        assert open_shared(ta) * open_shared(tb) % N == open_shared(tc)
        assert open_shared(random_nonzero_shared()) != 0
    assert beaver_triple() != beaver_triple()
    for _ in range(50):
        x = secrets.randbelow(N)
        y = secrets.randbelow(N)
        sx, sy = share(x), share(y)
        assert open_shared(multiply(sx, sy, beaver_triple())) == (x * y) % N
        assert open_shared(multiply(sx, sx, beaver_triple())) == (x * x) % N
    x, y = secrets.randbelow(N), secrets.randbelow(N)
    sx, sy = share(x), share(y)
    ta, tb, tc = beaver_triple()
    bad = (ta, tb, add_const(tc, 1))
    assert open_shared(multiply(sx, sy, bad)) == (x * y + 1) % N
    x1, x2 = secrets.randbelow(N), secrets.randbelow(N)
    ta, tb, tc = beaver_triple()
    eps1 = open_shared(sub(share(x1), ta))
    eps2 = open_shared(sub(share(x2), ta))
    assert (eps1 - eps2) % N == (x1 - x2) % N
    print("Reusing a triple leaks x1 - x2: never reuse triples!")
    for _ in range(50):
        k = secrets.randbelow(N - 1) + 1
        sk = share(k)
        k_inv = invert(sk, random_nonzero_shared(), beaver_triple())
        assert open_shared(k_inv) == pow(k, -1, N)
        assert (open_shared(k_inv) * k) % N == 1
    try:
        invert(share(0), random_nonzero_shared(), beaver_triple())
        assert False, "inverting zero must raise ValueError"
    except ValueError:
        print("Inverting zero is refused: k*b = 0 has no inverse.")
    k1, k2 = secrets.randbelow(N - 1) + 1, secrets.randbelow(N - 1) + 1
    mask = random_nonzero_shared()
    c1 = open_shared(multiply(share(k1), mask, beaver_triple()))
    c2 = open_shared(multiply(share(k2), mask, beaver_triple()))
    assert (c1 * pow(c2, -1, N)) % N == (k1 * pow(k2, -1, N)) % N
    print("Reusing a mask leaks k1/k2: never reuse masks!")
    for _ in range(50):
        d = secrets.randbelow(N - 1) + 1
        sd = share(d)
        assert lift(sd).format() == point_from_scalar(d).format()
        x, y = secrets.randbelow(N - 1) + 1, secrets.randbelow(N - 1) + 1
        sx = share(x)
        sy = share(y)
        assert lift(add(sx, sy)).format() == PublicKey.combine_keys([lift(sx), lift(sy)]).format()
    print("All tests have passed!")