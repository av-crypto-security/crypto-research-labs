import random
from hashlib import sha256

p_hex = '''ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'''.replace('\n', '').replace(' ', '')
p = int(p_hex, 16)
g = 2

a = random.randrange(1, p)         # randint()
b = random.randrange(1, p)         # randint()

def modexp(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

A = modexp(g, a, p)         # pow(), big num method for (g ** a) % p
B = modexp(g, b, p)         # pow(), big num method for (g ** b) % p

s1 = modexp(B, a, p)
s2 = modexp(A, b, p)
assert s1 == s2
print('Big DH shared secret is set')

derive_key = sha256(str(s1).encode()).hexdigest()

print("Alice's public:", A)
print("Bob's public:", B)
print("Shared secret:", s1)
print("SHA-256 derived key:", derive_key)
