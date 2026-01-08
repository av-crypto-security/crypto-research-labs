# Educational demo: simple LWE-like KEM with reconciliation + HKDF + MAC (HMAC-SHA256).
# Demonstrates KEM+MAC flow and seed-mode (precompute).
# NOT secure; for demonstration only.

import os, hashlib, hmac, random

# PARAMETERS (tiny for demo)
q = 97       # modulus
dim = 4      # vector dimension (small)
noise_range = (-1,0,1)

def sample_small_vec():
    return [random.choice(noise_range) for _ in range(dim)]

def vec_add(u,v): return [(a+b) % q for a,b in zip(u,v)]
def vec_sub(u,v): return [(a-b) % q for a,b in zip(u,v)]
def dot(u,v): return sum((a*b) for a,b in zip(u,v)) % q
def scalar_mul_vec(c, v): return [(c*x) % q for x in v]

# Simple reconciliation: client encodes bits by adding offset ~ q//4 or 3q//4,
# server decodes by thresholding around q/2.
def encode_bits_to_vec(bits):
    # bits length must be <= dim; pad zeros
    bits = bits + [0]*(dim - len(bits))
    return [ (q//4 if b==0 else 3*(q//4)) % q for b in bits ]

def decode_vec_to_bits(vec):
    out = []
    for x in vec:
        # map to minimal representative
        val = x % q
        # if near 0 region -> 0, if near 3q/4 region -> 1; threshold q//2
        out.append(0 if abs(val - 0) < abs(val - (3*(q//4)%q)) else 1)
    return out

# HKDF (simple)
def hkdf_extract(salt, ikm):
    if salt is None: salt = bytes([0]*32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, L=32):
    t=b""; okm=b""; i=1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i+=1
    return okm[:L]

def kdf_from_shared(shared_bytes):
    prk = hkdf_extract(None, shared_bytes)
    return hkdf_expand(prk, b"KEM+MAC demo context", 32)

# ---------------- KEM (toy LWE-like) ----------------
# KeyGen: public A (matrix), secret s (small), t = A*s + e
def keygen():
    A = [[random.randrange(q) for _ in range(dim)] for __ in range(dim)]
    s = sample_small_vec()
    e = sample_small_vec()
    # compute t = A*s + e  (matrix-vector)
    t = []
    for row in A:
        t.append( (sum((a*b) for a,b in zip(row,s)) + sum(e)) % q )  # simple aggregating for demo
    return {'A':A, 's':s, 'e':e, 't':t}

# Encaps (client): chooses r, computes u = A*r + e1, v = t*r + e2 + encode(m_bits)
def encapsulate(pk_t, A):
    r = sample_small_vec()
    e1 = sample_small_vec()
    e2 = sample_small_vec()
    # u = A*r + e1  (vector)
    u = []
    for row in A:
        u.append((sum(a*b for a,b in zip(row,r)) + sum(e1)) % q)
    # v = t*r + e2 + m_enc  (t is vector)
    tr = (sum((ti*ri) for ti,ri in zip(pk_t, r))) % q
    # create v as vector by repeating tr + noise + m_enc entries
    m_bits = [ random.choice([0,1]) for _ in range(2) ]  # demo short message bits
    m_enc = encode_bits_to_vec(m_bits)
    v = []
    for i in range(dim):
        v.append((tr + e2[i] + m_enc[i]) % q)
    # shared secret material to derive K on client side: use m_bits for demo (client knows m)
    shared = bytes(m_bits)
    return (u, v, shared, m_bits, r)

# Decaps (server): compute u*s, then compute v - u*s -> decode m
def decaps(sk_s, ct_u, ct_v, A):
    # us = u * s (dot of u and s repeated to vector)
    us_dot = sum(ui*si for ui,si in zip(ct_u, sk_s)) % q
    # compute v_minus_us vector
    v_minus_us = [ (vi - us_dot) % q for vi in ct_v ]
    # decode bits
    m_rec = decode_vec_to_bits(v_minus_us)
    shared = bytes(m_rec[:2])   # same length used by client
    return m_rec, shared

# ---------------- MAC (HMAC-SHA256) ----------------
def mac(k, msg): return hmac.new(k, msg, hashlib.sha256).digest()
def mac_verify(k, msg, tag): return hmac.compare_digest(mac(k,msg), tag)

# ---------------- Demo flows ----------------
def kem_mac_flow_demo():
    # Keygen (server)
    server = keygen()
    A = server['A']; s = server['s']; t = server['t']
    print("Server public t:", t)
    # Client encaps
    u, v, shared_client, m_bits, r = encapsulate(t, A)
    print("Client m_bits:", m_bits)
    # Client derives symmetric key K from shared_client (we use simple KDF)
    K_client = kdf_from_shared(shared_client)
    tag = mac(K_client, b"AUTH||" + bytes(m_bits))
    # Server decaps
    m_rec, shared_server = decaps(s, u, v, A)
    print("Server recovered m_bits:", m_rec[:2])
    K_server = kdf_from_shared(shared_server)
    ok = mac_verify(K_server, b"AUTH||" + bytes(m_rec[:2]), tag)
    return ok

def seed_mode_demo(precompute_N=4):
    # Demonstrate precompute: generate a set of (ct,u,v,shared) offline and later use
    server = keygen()
    A = server['A']; s = server['s']; t = server['t']
    buffer = []
    for i in range(precompute_N):
        u,v,shared,m_bits,r = encapsulate(t, A)
        buffer.append((u,v,shared,m_bits))
    # simulate online: take one precomputed capsule and perform MAC/verify quickly
    u,v,shared,m_bits = buffer.pop()
    Kc = kdf_from_shared(shared)
    tag = mac(Kc, b"AUTH||" + bytes(m_bits))
    m_rec, shared_server = decaps(s,u,v,A)
    Ks = kdf_from_shared(shared_server)
    return mac_verify(Ks, b"AUTH||" + bytes(m_rec[:2]), tag)

if __name__ == "__main__":
    print("KEM+MAC demo (toy):")
    ok = kem_mac_flow_demo()
    print("KEM+MAC verification OK?", ok)
    print("Seed-mode precompute demo:", seed_mode_demo())
