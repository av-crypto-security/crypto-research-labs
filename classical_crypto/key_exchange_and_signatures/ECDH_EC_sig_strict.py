# Demo:
#  - ECDH for key exchange (confidentiality),
#  - ECDSA-like signing for authentication (integrity + proof of possession).
# With minimal safety checks: curve validation, subgroup check, range checks.

import random, hashlib

# Curve params (toy curve, not secure!)
p = 233970423115425145524320034830162017933
a = -95051
b = 11279326
G = (182, 85518893674295321206118380980485522083)
order = 29246302889428143187362802287225875743
INFINITY = None

# --------------------
# Field / EC helpers
# --------------------
def inv_mod(x, m): return pow(x, -1, m)

def is_on_curve(P):
    if P is None: return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

def point_add(P, Q):
    if P is INFINITY: return Q
    if Q is INFINITY: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return INFINITY
    if P == Q:  # doubling
        if y1 % p == 0: return INFINITY
        lam = ((3*x1*x1 + a) * inv_mod(2*y1 % p, p)) % p
    else:       # addition
        if (x2 - x1) % p == 0: return INFINITY
        lam = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def point_double(P): return point_add(P, P)

# Montgomery ladder for scalar multiplication
def scalarmult_point(P, k):
    if k % order == 0 or P is INFINITY: return INFINITY
    R0, R1 = INFINITY, P
    for i in reversed(range(order.bit_length())):
        bit = (k >> i) & 1
        if bit == 0:
            R1 = point_add(R0, R1)
            R0 = point_double(R0)
        else:
            R0 = point_add(R0, R1)
            R1 = point_double(R1)
    return R0

# --------------------
# Validation helpers
# --------------------
def validate_point(P):
    """Check that point is valid: on curve and in subgroup of order."""
    if not is_on_curve(P):
        return False
    R = scalarmult_point(P, order)
    return R is INFINITY

# --------------------
#  ECDH (key exchange)
# --------------------
def ecdh_keypair():
    """Generate (secret, public) for ECDH with safe range check."""
    while True:
        d = random.randrange(1, order)  # secret in [1, order-1]
        Q = scalarmult_point(G, d)
        if validate_point(Q):
            return d, Q

def ecdh_shared(my_secret, peer_pub):
    """Compute shared EC point from peer's pubkey with validation."""
    if not validate_point(peer_pub):
        raise ValueError("Invalid peer public key")
    S = scalarmult_point(peer_pub, my_secret)
    if S is INFINITY:
        raise RuntimeError("Shared point at infinity, abort")
    return S

# --------------------
#  ECDSA-like signature (authentication)
# --------------------
def sha256_int(m: bytes) -> int:
    return int.from_bytes(hashlib.sha256(m).digest(), 'big')

def sign(msg: bytes, d: int):
    """Sign message with secret scalar d."""
    z = sha256_int(msg) % order
    while True:
        k = random.randrange(1, order)
        xk, _ = scalarmult_point(G, k)
        if xk is None:  # degenerate case
            continue
        r = xk % order
        if r == 0: continue
        s = (inv_mod(k, order) * (z + r*d)) % order
        if s == 0: continue
        return (r, s)

def verify(msg: bytes, sig, Q):
    """Verify signature with public key Q."""
    if not validate_point(Q):
        return False
    r, s = sig
    if not (1 <= r < order and 1 <= s < order):
        return False
    z = sha256_int(msg) % order
    w = inv_mod(s, order)
    u1, u2 = (z*w) % order, (r*w) % order
    P = point_add(scalarmult_point(G, u1), scalarmult_point(Q, u2))
    if P is INFINITY: return False
    return (P[0] % order) == r

# --------------------
# Demo
# --------------------
if __name__ == "__main__":
    print("=== ECDH key exchange ===")
    da, Qa = ecdh_keypair()
    db, Qb = ecdh_keypair()
    Sa = ecdh_shared(da, Qb)
    Sb = ecdh_shared(db, Qa)
    print("Alice shared:", Sa)
    print("Bob   shared:", Sb)
    print("Shared equal?", Sa == Sb)

    print("\n=== ECDSA-like authentication ===")
    msg = b"Authenticate me!"
    sig = sign(msg, da)     # Alice signs with her secret da
    ok  = verify(msg, sig, Qa)  # Anyone verifies with Alice's public Qa
    print("Signature:", sig)
    print("Valid?", ok)
