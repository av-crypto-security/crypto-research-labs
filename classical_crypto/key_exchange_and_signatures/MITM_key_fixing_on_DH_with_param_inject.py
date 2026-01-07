# ------------------------------------------------------------------- install pycryptodome first ------------------------------------
import os
from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

def sha1_key(s: int) -> bytes:
    return sha1(str(s).encode()).digest()[:16]

def aes_encrypt(key: bytes, msg: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(msg, 16)), iv

def aes_decrypt(key: bytes, ct: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16)

class Participant:
    def __init__(self, name: str, p: int, g: int):
        self.name = name
        self.p = p
        self.g = g
        self.private = int.from_bytes(os.urandom(128), 'big') % p
        self.public = pow(g, self.private, p)
        self.shared = None
    def compute_shared_secret(self, other_pub: int) -> int:
        self.shared = pow(other_pub, self.private, self.p)
        return self.shared
    def derive_key(self) -> bytes:
        return sha1_key(self.shared)

alice = Participant('Alice', p, g)
bob = Participant('Bob', p, g)
mallory = Participant('Mallory', p, g)

message_from_alice = (p, g, alice.public)

message_from_mallory_to_bob = (p, g, p)

bob.compute_shared_secret(p)                         # s = (p ** b) % p == 0
key_bob = bob.derive_key()
message_from_bob = bob.public

alice.compute_shared_secret(p)                       # s = (p ** a) % p == 0
key_alice = alice.derive_key()
plaintext_from_alice = b"Hi Bob, it's Alice"
ct_a, iv_a = aes_encrypt(key_alice, plaintext_from_alice)

key_mallory = sha1_key(0)
decrypted_by_mallory_a = aes_decrypt(key_mallory, ct_a, iv_a)

ct_b, iv_b = aes_encrypt(key_bob, decrypted_by_mallory_a)
decrypted_by_mallory_b = aes_decrypt(key_mallory, ct_b, iv_b)

decrypted_by_mallory_a.decode(), decrypted_by_mallory_b.decode()
