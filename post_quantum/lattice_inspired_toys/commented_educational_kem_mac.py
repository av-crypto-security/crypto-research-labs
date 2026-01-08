# Educational demonstration script: simplified LWE-like KEM + reconciliation + HKDF + HMAC.
# All code is purely educational (NOT cryptographically secure).
# Comments explain step-by-step what is happening and why.

import os                # for random byte generation (used in simple variants)
import hashlib           # for SHA-256 (KDF / hashing)
import hmac              # for HMAC-SHA256 (MAC)
import random            # for generating small random vectors

# -----------------------------
# PARAMETERS (intentionally tiny for demonstration)
# -----------------------------
q = 97                   # arithmetic modulus (real Kyber uses q = 3329, etc.)
dim = 4                  # vector dimension (small for clarity)
noise_range = (-1, 0, 1) # range of "small noise" for secrets/errors

# -----------------------------
# Utilities: vector operations (mod q)
# -----------------------------
def sample_small_vec():
    """Returns a vector of length dim with small coefficients (noise/secret)."""
    return [random.choice(noise_range) for _ in range(dim)]

def vec_add(u, v):
    """Component-wise vector addition modulo q."""
    return [(a + b) % q for a, b in zip(u, v)]

def vec_sub(u, v):
    """Component-wise vector subtraction modulo q."""
    return [(a - b) % q for a, b in zip(u, v)]

def dot(u, v):
    """Dot product of two vectors over integers (then reduced modulo q)."""
    return sum((a * b) for a, b in zip(u, v)) % q

def scalar_mul_vec(c, v):
    """Multiply a vector by a scalar modulo q."""
    return [(c * x) % q for x in v]

# -----------------------------
# Simple reconciliation scheme (encoding/decoding bits into coefficients)
# -----------------------------
# Idea: encode bit 0 as a value near q/4, bit 1 near 3q/4.
# With small noise, the receiver recovers the bit using a threshold.

def encode_bits_to_vec(bits):
    """
    Encodes a list of bits into a vector of length dim.
    - Pads with zeros if bits are shorter than dim.
    - bit == 0 -> q//4, bit == 1 -> 3*(q//4).
    """
    bits = bits + [0] * (dim - len(bits))  # zero-padding to length dim
    return [(q // 4 if b == 0 else 3 * (q // 4)) % q for b in bits]

def decode_vec_to_bits(vec):
    """
    Decodes vector coefficients back into bits.
    Simple rule: compare distance to 0 and to 3q/4 (mod q).
    """
    out = []
    target_one = (3 * (q // 4)) % q
    for x in vec:
        val = x % q
        # closer to 0 -> bit 0, otherwise -> bit 1
        out.append(0 if abs(val - 0) < abs(val - target_one) else 1)
    return out

# -----------------------------
# Simple HKDF (extract/expand) for symmetric key derivation
# -----------------------------
def hkdf_extract(salt, ikm):
    """HKDF-extract using HMAC-SHA256. If salt is None, use a zero salt."""
    if salt is None:
        salt = bytes([0] * 32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, L=32):
    """HKDF-expand (iterative), returns L bytes of key material."""
    t = b""
    okm = b""
    i = 1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:L]

def kdf_from_shared(shared_bytes):
    """
    Utility: derive a 32-byte symmetric key from some shared material using HKDF.
    In real schemes, shared_bytes come from reconciliation output.
    """
    prk = hkdf_extract(None, shared_bytes)
    return hkdf_expand(prk, b"KEM+MAC demo context", 32)

# -----------------------------
# KEM (toy LWE-like) — heavily simplified
# -----------------------------
# KeyGen:
# - generate public matrix A (dim x dim),
# - secret vector s (small),
# - error vector e (small),
# - public vector t = A*s + e.
def keygen():
    A = [[random.randrange(q) for _ in range(dim)] for __ in range(dim)]
    s = sample_small_vec()  # secret small vector
    e = sample_small_vec()  # error vector
    t = []
    for row in A:
        # For demonstration: sum of products + summed noise (simplified)
        t.append((sum((a * b) for a, b in zip(row, s)) + sum(e)) % q)
    return {'A': A, 's': s, 'e': e, 't': t}

# Encapsulation (client):
# - choose r, noises e1, e2,
# - compute u = A*r + e1,
# - compute v = t*r + e2 + m_enc.
def encapsulate(pk_t, A):
    r = sample_small_vec()    # ephemeral small vector
    e1 = sample_small_vec()   # noise for u
    e2 = sample_small_vec()   # noise for v

    # u = A*r + e1
    u = []
    for row in A:
        u.append((sum(a * b for a, b in zip(row, r)) + sum(e1)) % q)

    # t · r
    tr = (sum((ti * ri) for ti, ri in zip(pk_t, r))) % q

    # Client encodes a short demo message (e.g., 2 bits)
    m_bits = [random.choice([0, 1]) for _ in range(2)]
    m_enc = encode_bits_to_vec(m_bits)

    # v = tr + e2_i + m_enc_i
    v = []
    for i in range(dim):
        v.append((tr + e2[i] + m_enc[i]) % q)

    # Shared secret material on client side (educationally just the bits)
    shared = bytes(m_bits)

    # Return ciphertext and demo internals
    return (u, v, shared, m_bits, r)

# Decapsulation (server):
# - compute u*s,
# - subtract from v,
# - recover message bits via threshold decoding.
def decaps(sk_s, ct_u, ct_v, A):
    us_dot = sum(ui * si for ui, si in zip(ct_u, sk_s)) % q
    v_minus_us = [(vi - us_dot) % q for vi in ct_v]
    m_rec = decode_vec_to_bits(v_minus_us)
    shared = bytes(m_rec[:2])
    return m_rec, shared

# -----------------------------
# MAC (HMAC-SHA256) for authentication / confirmation
# -----------------------------
def mac(k, msg):
    """Returns HMAC-SHA256 of msg under key k."""
    return hmac.new(k, msg, hashlib.sha256).digest()

def mac_verify(k, msg, tag):
    """Constant-time-like comparison of HMAC values."""
    return hmac.compare_digest(mac(k, msg), tag)

# -----------------------------
# Demonstration scenarios
# -----------------------------
def kem_mac_flow_demo():
    # 1) Server key generation
    server = keygen()
    A = server['A']; s = server['s']; t = server['t']
    print("Server public t:", t)

    # 2) Client encapsulation
    u, v, shared_client, m_bits, r = encapsulate(t, A)
    print("Client m_bits (sent):", m_bits)

    # 3) Client derives symmetric key and MAC
    K_client = kdf_from_shared(shared_client)
    tag = mac(K_client, b"AUTH||" + bytes(m_bits))

    # 4) Server decapsulation
    m_rec, shared_server = decaps(s, u, v, A)
    print("Server recovered m_bits:", m_rec[:2])

    # 5) Server derives key and verifies MAC
    K_server = kdf_from_shared(shared_server)
    ok = mac_verify(K_server, b"AUTH||" + bytes(m_rec[:2]), tag)
    return ok

def seed_mode_demo(precompute_N=4):
    """
    Demonstration of precompute (seed-mode):
    - server precomputes N capsules offline,
    - online client uses one precomputed capsule (fast, low-cost).
    """
    server = keygen()
    A = server['A']; s = server['s']; t = server['t']
    buffer = []

    # Offline precomputation
    for i in range(precompute_N):
        u, v, shared, m_bits, r = encapsulate(t, A)
        buffer.append((u, v, shared, m_bits))

    # Online usage
    u, v, shared, m_bits = buffer.pop()
    Kc = kdf_from_shared(shared)
    tag = mac(Kc, b"AUTH||" + bytes(m_bits))

    m_rec, shared_server = decaps(s, u, v, A)
    Ks = kdf_from_shared(shared_server)
    return mac_verify(Ks, b"AUTH||" + bytes(m_rec[:2]), tag)

# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    print("KEM+MAC demo (toy):")
    ok = kem_mac_flow_demo()
    print("KEM+MAC verification OK?", ok)
    print("Seed-mode precompute demo:", seed_mode_demo())
