import random, hashlib

p = 233970423115425145524320034830162017933
g = 2

def modexp(base, exp, mod):
    result = 1
    base % mod
    while exp > 0:
        if exp % 2 == 1:
            base = (base*base) % mod
        result = (result*base) % mod
        exp //= 2
    return result

def key_pair():
    private = random.randrange(1, p)
    pub = modexp(g, private, p)
    return private, pub

def shared(my_private, peer_pub):
    if peer_pub == p or g == 1 or g == p - 1 or g == p:
        raise ValueError('MITM, abort')
    result = modexp(peer_pub, my_private, p)
    return result

def derive(s: int) -> bytes:
    return hashlib.sha256(s.to_bytes((s.bit_length()+7)// 8 or 1, 'big')).digest()[:16]

if __name__ == '__main__':
    print("=== Classic DH key exchange educational demo ===")
    a, A = key_pair()
    b, B = key_pair()
    S1 = shared(a, B)
    S2 = shared(b, A)
    print("Alice's public:", A)
    print("Bob's public:", B)
    print("Alice's shared:", S1)
    print("Bob's shared:", S2)
    print("Shared equal?", S1 == S2)
    derived_key = derive(S1)
    print("Derived SHA256 key:", derived_key.hex())
