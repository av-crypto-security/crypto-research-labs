# --------------------------------------------------------- with pycryptodome ---------------------------------------------------------

import os, hashlib, secrets
from dataclasses import dataclass
from Crypto.Cipher import AES

# ---------- Utils ----------
def sha1_key(s: int) -> bytes:
    # K = SHA1(s)[0:16]
    return hashlib.sha1(s.to_bytes((s.bit_length()+7)//8 or 1, 'big')).digest()[:16]

def pkcs7_pad(b: bytes, block=16) -> bytes:
    n = block - (len(b) % block)
    return b + bytes([n])*n

def pkcs7_unpad(b: bytes, block=16) -> bytes:
    n = b[-1]
    if n == 0 or n > block or b[-n:] != bytes([n])*n:
        raise ValueError("bad padding")
    return b[:-n]

def aes_cbc_encrypt(key: bytes, iv: bytes, msg: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(msg))

def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    return pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct))

# ---------- Protocol Parties ----------
@dataclass
class Params:
    p: int
    g: int

@dataclass
class Party:
    params: Params
    a: int = None
    A: int = None
    s: int = None
    key: bytes = None

    def start(self):
        self.a = secrets.randbelow(self.params.p - 2) + 2   # 2..p-1
        self.A = pow(self.params.g, self.a, self.params.p)
        return self.A

    def finish(self, B: int):
        self.s = pow(B, self.a, self.params.p)
        self.key = sha1_key(self.s)

    def send(self, msg: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(16)
        ct = aes_cbc_encrypt(self.key, iv, msg)
        return ct, iv

    def recv(self, ct: bytes, iv: bytes) -> bytes:
        return aes_cbc_decrypt(self.key, iv, ct)

# ---------- Eve (rewrites g and decrypts) ----------
class MITM:
    def __init__(self, malicious_g: str):
        self.mode = malicious_g  # "1", "p", "p-1"
        self.last_publics = None # (A, B)
        self.params_seen = None  # (p, g_real, g_sent)

    def rewrite_params(self, p: int, g_real: int) -> Params:
        if self.mode == "1":
            g_bad = 1
        elif self.mode == "p":
            g_bad = p
        elif self.mode == "p-1":
            g_bad = p - 1
        else:
            raise ValueError("bad mode")
        self.params_seen = (p, g_real, g_bad)
        return Params(p, g_bad)

    def tap_publics(self, A: int, B: int):
        self.last_publics = (A, B)

    # ---------------------------------------- compute the predictible s ----------------------------------
    def guess_s(self) -> int:
        p, g_real, g_bad = self.params_seen
        A, B = self.last_publics

        if g_bad == 1:
            return 1 % p
        if g_bad % p == 0:  # g == p
            return 0
        if g_bad == p - 1:  # g == -1 mod p
            # A = (-1)^a -> 1 (a even) if p-1 (a odd)
            # B similarly. s = (-1)^(ab). If A==1 or B==1 -> s=1. Else s=p-1.
            if A == 1 or B == 1:
                return 1
            return p - 1
        raise AssertionError

    def crack_key(self) -> bytes:
        s = self.guess_s()
        return sha1_key(s)

# ---------- Attacks Demo ----------
def demo(mode: str):
    # Large prime p NIST-like:
    p = int(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
        16
    )
    g_real = 2

    mitm = MITM(mode)
    # MITM substitutes g in message "Send 'p','g'"
    params_for_victims = mitm.rewrite_params(p, g_real)

    alice = Party(params_for_victims)
    bob   = Party(params_for_victims)

    # A->B: "A"; B->A: "B"
    A = alice.start()
    B = bob.start()
    mitm.tap_publics(A, B)

    alice.finish(B)
    bob.finish(A)

    # ciphertext exchange AES-CBC(SHA1(s)[0:16], iv, msg) + iv
    msgA = b"hi bob, it's alice"
    msgB = b"hi alice, it's bob"
    ctA, ivA = alice.send(msgA)
    ctB, ivB = bob.send(msgB)

    # MITM suggests s and decrypts both messages
    K = mitm.crack_key()
    decA = aes_cbc_decrypt(K, ivA, ctA)
    decB = aes_cbc_decrypt(K, ivB, ctB)

    # correctness check
    assert decA == msgA and decB == msgB
    return {
        "mode": mode,
        "g_sent": params_for_victims.g,
        "A": A, "B": B,
        "shared_s_guess": int.from_bytes(hashlib.sha1(decA).digest()[:1], 'big')*0 + (0 if mitm.guess_s()==0 else mitm.guess_s()),  # just show s value
        "alice_key": alice.key.hex(),
        "bob_key":   bob.key.hex(),
        "mitm_key":  K.hex(),
        "alice_msg": decA.decode(),
        "bob_msg":   decB.decode(),
    }

if __name__ == "__main__":
    for mode in ("1", "p", "p-1"):
        r = demo(mode)
        print(f"\n=== g = {r['g_sent']} (mode {r['mode']}) ===")
        print("A =", r["A"])
        print("B =", r["B"])
        print("MITM key =", r["mitm_key"])
        print("Alice key=", r["alice_key"])
        print("Bob key  =", r["bob_key"])
        print("Alice→Bob:", r["alice_msg"])
        print("Bob→Alice:", r["bob_msg"])
