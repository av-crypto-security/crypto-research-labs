# Toy Kyber with simple reconciliation

import random, hashlib

q = 17
N = 4
root = 13
root_inv = pow(root, -1, q)
inv_N = pow(N, -1, q)

def ntt(a, root):
    A = a[:]
    n = len(A)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit; bit >>= 1
        j ^= bit
        if i < j:
            A[i], A[j] = A[j], A[i]
    length = 2
    while length <= n:
        wlen = pow(root, n // length, q)
        for i in range(0, n, length):
            w = 1
            for j in range(i, i + length // 2):
                u = A[j]
                v = (A[j + length // 2] * w) % q
                A[j] = (u + v) % q
                A[j + length // 2] = (u - v) % q
                w = (w * wlen) % q
        length <<= 1
    return A

def intt(A, root_inv):
    n = len(A)
    a = ntt(A, root_inv)
    return [(x * inv_N) % q for x in a]

def poly_mul(a, b):
    A = ntt(a, root); B = ntt(b, root)
    C = [(x*y) % q for x,y in zip(A,B)]
    return intt(C, root_inv)

def rnd_small_vector():
    return [random.choice([-1,0,1]) for _ in range(N)]

def vec_add(u,v): return [(a+b)%q for a,b in zip(u,v)]
def vec_sub(u,v): return [(a-b)%q for a,b in zip(u,v)]

# --- KeyGen ---
A = [random.randrange(q) for _ in range(N)]
s = rnd_small_vector()
e = rnd_small_vector()
t = vec_add(poly_mul(A,s), e)

# --- Encaps ---
def encaps(pk_t):
    r = rnd_small_vector(); e1 = rnd_small_vector(); e2 = rnd_small_vector()
    u = vec_add(poly_mul(A, r), e1)
    # encode message bits into vector m_enc
    m_bits = [random.choice([0,1]) for _ in range(N)]
    m_enc = [bit*(q//2) for bit in m_bits]  # 0 → 0, 1 → ~q/2
    v = vec_add(vec_add(poly_mul(pk_t, r), e2), m_enc)
    K = hashlib.sha256(bytes(m_bits)).hexdigest()
    return (u,v,K,m_bits)

# --- Reconciliation (Decaps) ---
def decode_coeff(c):
    # decide 0 if closer to 0, 1 if closer to q/2
    if abs(c - 0) < abs(c - q//2):
        return 0
    else:
        return 1

def decaps(sk_s, ct_u, ct_v):
    us = poly_mul(ct_u, sk_s)
    diff = vec_sub(ct_v, us)
    m_rec = [decode_coeff(c) for c in diff]
    K = hashlib.sha256(bytes(m_rec)).hexdigest()
    return m_rec, K

# Demo
u,v,Kc,mbits = encaps(t)
m_rec,Ks = decaps(s,u,v)

print("Message bits (client) :", mbits)
print("Message bits (server) :", m_rec)
print("Keys equal? ", Kc==Ks)
