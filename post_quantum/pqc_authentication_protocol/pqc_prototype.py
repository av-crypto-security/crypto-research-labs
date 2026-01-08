#!/usr/bin/env python3
# pqc_prototype.py — robust prototype for KEM+MAC and Signature-Auth using oqs-python
import argparse
import time
import statistics
import secrets
import hmac
import hashlib
import json
import sys

# pyliboqs (oqs)
try:
    import oqs
except Exception:
    oqs = None

# ------------------------- HKDF (RFC5869-like) -------------------------
def hkdf_extract(salt, ikm, hashmod=hashlib.sha256):
    if salt is None:
        salt = bytes([0] * hashmod().digest_size)
    return hmac.new(salt, ikm, hashmod).digest()

def hkdf_expand(prk, info, length, hashmod=hashlib.sha256):
    hash_len = hashmod().digest_size
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashmod).digest()
        okm += t
    return okm[:length]

# ------------------------- MAC (HMAC-SHA256) ------------------------------
def produce_mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_mac(key: bytes, data: bytes, tag: bytes) -> bool:
    expected = produce_mac(key, data)
    return hmac.compare_digest(expected, tag)

# ------------------------- PQC Wrappers (robust for oqs-python variants) ---------------------------
class PQCKEM:
    def __init__(self, alg_name: str = "Kyber512"):
        if oqs is None:
            raise RuntimeError("pyliboqs (oqs) not available. Install pyliboqs.")
        self.alg_name = alg_name

    def keygen(self):
        """Return (sk, pk). Works with different oqs-python behaviors."""
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            res = kem.generate_keypair()
            # generate_keypair may return public key only or a tuple.
            if isinstance(res, (tuple, list)) and len(res) >= 2:
                pk = res[0]
                sk = res[1]
            else:
                pk = res
                # export_secret_key is present in modern bindings
                if hasattr(kem, "export_secret_key"):
                    sk = kem.export_secret_key()
                else:
                    raise RuntimeError("oqs.KeyEncapsulation lacks export_secret_key; cannot obtain secret key.")
        return sk, pk

    def encaps(self, pk: bytes, info: bytes = b""):
        """Encapsulate to peer public key. Returns (ct, shared_secret)."""
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            # try modern names: encap_secret or encapsulate
            if hasattr(kem, "encap_secret"):
                ct, shared = kem.encap_secret(pk)
            elif hasattr(kem, "encapsulate"):
                ct, shared = kem.encapsulate(pk)
            else:
                raise RuntimeError("No encap method found on oqs.KeyEncapsulation object.")
        if info:
            prk = hkdf_extract(None, shared)
            shared = hkdf_expand(prk, info, len(shared))
        return ct, shared

    def decaps(self, sk: bytes, ct: bytes, info: bytes = b""):
        """Decapsulate ciphertext using secret key sk and return shared_secret."""
        # Some bindings accept secret_key parameter at construction.
        # Try creating object with secret_key first, then fallback to loading secret into object.
        try:
            # Try constructor with secret_key (works in some builds)
            with oqs.KeyEncapsulation(self.alg_name, secret_key=sk) as kem:
                if hasattr(kem, "decap_secret"):
                    shared = kem.decap_secret(ct)
                elif hasattr(kem, "decapsulate"):
                    shared = kem.decapsulate(ct)
                else:
                    raise RuntimeError("No decap method present on oqs.KeyEncapsulation instance.")
        except TypeError:
            # Fallback: construct object then load secret key
            with oqs.KeyEncapsulation(self.alg_name) as kem:
                if hasattr(kem, "load_secret_key"):
                    kem.load_secret_key(sk)
                elif hasattr(kem, "import_secret_key"):
                    kem.import_secret_key(sk)
                else:
                    # If no loader, try export/import flow (rare)
                    pass
                if hasattr(kem, "decap_secret"):
                    shared = kem.decap_secret(ct)
                elif hasattr(kem, "decapsulate"):
                    shared = kem.decapsulate(ct)
                else:
                    raise RuntimeError("No decap method present on oqs.KeyEncapsulation instance.")
        if info:
            prk = hkdf_extract(None, shared)
            shared = hkdf_expand(prk, info, len(shared))
        return shared

class PQCSIG:
    def __init__(self, alg_name: str = "Dilithium2"):
        if oqs is None:
            raise RuntimeError("pyliboqs (oqs) not available. Install pyliboqs.")
        self.alg_name = alg_name

    def keygen(self):
        """Return (sk, pk)."""
        with oqs.Signature(self.alg_name) as sig:
            res = sig.generate_keypair()
            # generate_keypair may return pk only or a tuple
            if isinstance(res, (tuple, list)) and len(res) >= 2:
                pk = res[0]
            else:
                pk = res
            if hasattr(sig, "export_secret_key"):
                sk = sig.export_secret_key()
            else:
                raise RuntimeError("oqs.Signature lacks export_secret_key; cannot obtain secret key.")
        return sk, pk

    def sign(self, sk: bytes, message: bytes):
        """Sign message with secret key sk (returns signature bytes)."""
        # Try constructor with secret_key (some builds), else import_secret_key
        try:
            with oqs.Signature(self.alg_name, secret_key=sk) as sig:
                sigb = sig.sign(message)
                return sigb
        except TypeError:
            with oqs.Signature(self.alg_name) as sig:
                if hasattr(sig, "import_secret_key"):
                    sig.import_secret_key(sk)
                elif hasattr(sig, "load_secret_key"):
                    sig.load_secret_key(sk)
                else:
                    raise RuntimeError("No import/load secret method on oqs.Signature.")
                sigb = sig.sign(message)
                return sigb

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature using pk (returns bool)."""
        # Try signature.verify(message, signature, pk) variations
        try:
            with oqs.Signature(self.alg_name) as sig:
                # some bindings have verify(message, signature, public_key) or verify(public_key, message, signature)
                if hasattr(sig, "verify"):
                    # try common variants
                    try:
                        return sig.verify(message, signature, pk)
                    except Exception:
                        try:
                            return sig.verify(pk, message, signature)
                        except Exception:
                            # fallback: load public key and call verify(message, signature)
                            if hasattr(sig, "load_public_key"):
                                sig.load_public_key(pk)
                                return sig.verify(message, signature)
                            else:
                                # last resort: try module-level verify if exists
                                raise
                else:
                    raise RuntimeError("No verify method on oqs.Signature instance.")
        except Exception:
            return False

# ------------------------- Protocol logic -------------------------------
def derive_keys_from_seed(seed: bytes, ctx: bytes = b"auth-context"):
    prk = hkdf_extract(None, seed)
    okm = hkdf_expand(prk, ctx, 64)
    sk = okm[:32]
    pk = okm[32:64]
    return sk, pk

def run_kem_mac_session(kem: PQCKEM, pk_server: bytes, sk_server: bytes, ctx: bytes = b"ctx", nonce_client=None, nonce_server=None):
    if nonce_client is None:
        nonce_client = secrets.token_bytes(16)
    if nonce_server is None:
        nonce_server = secrets.token_bytes(16)
    n = nonce_client + nonce_server

    t0 = time.perf_counter()
    ct, K_client = kem.encaps(pk_server, info=n + ctx)
    t_enc = time.perf_counter() - t0

    t0 = time.perf_counter()
    K_server = kem.decaps(sk_server, ct, info=n + ctx)
    t_dec = time.perf_counter() - t0

    # Derive symmetric key (truncate)
    key = K_client[:32]
    t0 = time.perf_counter()
    tag = produce_mac(key, b"AUTH" + n + ctx)
    t_mac = time.perf_counter() - t0

    t0 = time.perf_counter()
    ok = verify_mac(K_server[:32], b"AUTH" + n + ctx, tag)
    t_macv = time.perf_counter() - t0

    return {
        'enc_time': t_enc, 'dec_time': t_dec, 'mac_time': t_mac, 'macv_time': t_macv,
        'success': ok, 'ct_len': len(ct), 'tag_len': len(tag)
    }

def run_signature_session(sig: PQCSIG, sk_client: bytes, pk_client: bytes, ctx: bytes = b"ctx", nonce_client=None, nonce_server=None):
    if nonce_client is None:
        nonce_client = secrets.token_bytes(16)
    if nonce_server is None:
        nonce_server = secrets.token_bytes(16)
    n = nonce_client + nonce_server

    t0 = time.perf_counter()
    signature = sig.sign(sk_client, b"AUTH" + n + ctx)
    t_sign = time.perf_counter() - t0

    t0 = time.perf_counter()
    ok = sig.verify(pk_client, b"AUTH" + n + ctx, signature)
    t_verify = time.perf_counter() - t0

    return {'sign_time': t_sign, 'verify_time': t_verify, 'sig_len': len(signature), 'success': ok}

# ------------------------- Bench harness --------------------------------
def bench_kem_mac(alg_name="Kyber512", niter=500):
    kem = PQCKEM(alg_name)
    sk, pk = kem.keygen()

    enc_times = []
    dec_times = []
    mac_times = []
    macv_times = []
    ct_lens = []
    tag_lens = []
    successes = 0
    for _ in range(niter):
        res = run_kem_mac_session(kem, pk, sk, ctx=b'ctx')
        enc_times.append(res['enc_time'])
        dec_times.append(res['dec_time'])
        mac_times.append(res['mac_time'])
        macv_times.append(res['macv_time'])
        ct_lens.append(res['ct_len'])
        tag_lens.append(res['tag_len'])
        successes += 1 if res['success'] else 0

    return {
        'enc_med': statistics.median(enc_times),
        'dec_med': statistics.median(dec_times),
        'mac_med': statistics.median(mac_times),
        'macv_med': statistics.median(macv_times),
        'ct_len_med': statistics.median(ct_lens),
        'tag_len_med': statistics.median(tag_lens),
        'success_rate': successes / niter
    }

def bench_sig(alg_name="Dilithium2", niter=500):
    sig = PQCSIG(alg_name)
    sk, pk = sig.keygen()

    sign_times = []
    verify_times = []
    sig_lens = []
    successes = 0
    for _ in range(niter):
        res = run_signature_session(sig, sk, pk, ctx=b'ctx')
        sign_times.append(res['sign_time'])
        verify_times.append(res['verify_time'])
        sig_lens.append(res['sig_len'])
        successes += 1 if res['success'] else 0

    return {
        'sign_med': statistics.median(sign_times),
        'verify_med': statistics.median(verify_times),
        'sig_len_med': statistics.median(sig_lens),
        'success_rate': successes / niter
    }

# ------------------------- CLI ------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bench', action='store_true')
    parser.add_argument('--niter', type=int, default=500)
    parser.add_argument('--kem', type=str, default='Kyber512')
    parser.add_argument('--sig', type=str, default='Dilithium2')
    args = parser.parse_args()

    if oqs is None:
        print('pyliboqs (oqs) not available. Install with `pip install pyliboqs`.')
        return

    # Validate algorithm names against the installed oqs
    try:
        enabled_kems = tuple(oqs.get_enabled_kem_mechanisms())
        enabled_sigs = tuple(oqs.get_enabled_sig_mechanisms())
    except Exception:
        # fallback naming
        enabled_kems = tuple(oqs.get_enabled_kems())
        enabled_sigs = tuple(oqs.get_enabled_sigs())

    if args.kem not in enabled_kems:
        print("Requested KEM not available. Enabled KEMs:", enabled_kems)
        return
    if args.sig not in enabled_sigs:
        print("Requested SIG not available. Enabled SIGs:", enabled_sigs)
        return

    if args.bench:
        print(f'Running bench: niter={args.niter}, kem={args.kem}, sig={args.sig}')
        kem_res = bench_kem_mac(alg_name=args.kem, niter=args.niter)
        sig_res = bench_sig(alg_name=args.sig, niter=args.niter)

        summary = {'kem': kem_res, 'sig': sig_res}
        with open('pqc_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        print('Wrote pqc_summary.json')

        try:
            import matplotlib.pyplot as plt
            client = [kem_res['enc_med'] + kem_res['mac_med'], sig_res['sign_med']]
            server = [kem_res['dec_med'] + kem_res['macv_med'], sig_res['verify_med']]
            modes = ['KEM+MAC', 'SIG']
            e2e = [c + s for c, s in zip(client, server)]
            plt.figure(figsize=(6,4))
            plt.bar(modes, e2e)
            plt.ylabel('E2E time (s)')
            plt.title('PQC prototype E2E times (median)')
            plt.tight_layout()
            plt.savefig('pqc_plot.png')
            print('Saved pqc_plot.png')
        except Exception as e:
            print('Plot failed:', e)

if __name__ == '__main__':
    main()
