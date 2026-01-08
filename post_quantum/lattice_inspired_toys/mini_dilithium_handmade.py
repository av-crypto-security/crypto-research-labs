# Educational mini-Dilithium-like demo with a trivial "hint" reconciliation.
# NOT secure. For learning & demo only.

import hashlib, random

# PARAMETERS (very small for demo)
q = 97            # modulus
n = 3             # dimension
BOUND = 1         # smallness bound for secrets/y

# Utilities
def modq(v): return [x % q for x in v]
def mat_vec_mul(A, v): return [sum(a*x for a,x in zip(row,v)) % q for row in A]
def vec_add(u,v): return [(a+b) % q for a,b in zip(u,v)]
def vec_sub(u,v): return [(a-b) % q for a,b in zip(u,v)]
def scalar_vec_mul(c, v): return [(c*x) % q for x in v]

def sample_small(): return [random.choice([-1,0,1]) for _ in range(n)]
def bytes_from_vector(v): return bytes(((x % q) & 0xFF) for x in v)

# Tiny hash -> challenge vector (bits)
def hash_to_challenge(w, msg, length=n):
    h = hashlib.sha256()
    h.update(bytes_from_vector(w))
    h.update(msg)
    digest = h.digest()
    bits = []
    for b in digest:
        for i in range(8):
            bits.append((b >> i) & 1)
    return bits[:length]

# SIMPLE hint: for each coefficient of w keep a bit indicating whether w_i > q/2
def make_hint(w):
    return [1 if (wi % q) > (q//2) else 0 for wi in w]

def apply_hint(wprime, hint):
    # adjust wprime according to hint: if hint bit=1 and wprime small negative, add q
    # This is a toy operation to simulate 'helping' the verifier
    out = []
    for val, h in zip(wprime, hint):
        v = val % q
        if h == 1 and v < q//2:
            v = (v + q) % q
        out.append(v)
    return out

# ---------------- KeyGen ----------------
# Public matrix A (small ints)
A = [
    [12, 25, 7],
    [3,  18, 5],
    [21, 4,  9]
]

# Secrets
s1 = sample_small()   # small secret vector s1
s2 = sample_small()   # small secret s2
e = sample_small()    # error

t = vec_add(mat_vec_mul(A, s1), vec_add(s2, e))  # t = A*s1 + s2 + e (mod q)

print("=== KeyGen ===")
print("A =", A)
print("s1=", s1, "s2=", s2, "e=", e)
print("t =", t)
print()

# ---------------- Sign(msg) ----------------
def sign(msg):
    # 1) pick ephemeral y (small)
    y = sample_small()
    # 2) w = A * y
    w = mat_vec_mul(A, y)
    # 3) challenge c <- H(w || m) -> bit vector
    c = hash_to_challenge(w, msg, length=n)
    # 4) z = y + c * s1  (componentwise)
    cs = [ci * si for ci, si in zip(c, s1)]
    z = [(yi + csi) % q for yi, csi in zip(y, cs)]
    # produce hint from original w to help verifier (toy)
    hint = make_hint(w)
    # signature = (z, c, hint)
    return (z, c, hint)

# ---------------- Verify(msg, sig) ----------------
def verify(msg, sig):
    z, c, hint = sig
    # Az
    Az = mat_vec_mul(A, z)
    # c * t
    ct = [ (ci * ti) % q for ci, ti in zip(c, t) ]
    # w' = A*z - c*t
    wprime = vec_sub(Az, ct)
    # apply hint to adjust
    w_adj = apply_hint(wprime, hint)
    # recompute challenge
    cprime = hash_to_challenge(w_adj, msg, length=n)
    # check z small enough (loose check)
    def is_small(v):
        return all(abs((x if x <= q//2 else x - q)) <= (3*BOUND) for x in v)
    return (cprime == c) and is_small(z)

# ---------------- Demo ----------------
if __name__ == "__main__":
    M = b"hello mini-dilithium-handmade"
    sig = sign(M)
    ok = verify(M, sig)
    print("Signature valid?", ok)
    print("sig z:", sig[0])
    print("sig c:", sig[1])
    print("sig hint:", sig[2])
