# Post-Quantum Authentication Prototype

Minimal, self-contained **post-quantum authentication prototype**
based on **KEM + MAC** and **digital signatures**, implemented with
`oqs-python` (liboqs).

This is a **compact research prototype**, focused on correctness,
reproducibility, and performance measurements — not a full protocol.

---

## What is implemented

**Primitives**
- KEM: Kyber (default: Kyber512)
- Signature: Dilithium (default: Dilithium2)
- MAC: HMAC-SHA256
- KDF: HKDF (RFC 5869–style)

**Authentication models**
- **KEM + MAC**
  - Nonce-based context binding
  - Shared secret derivation via HKDF
  - Explicit MAC verification
- **Signature-based authentication**
  - Nonce-based challenge–response
  - Explicit sign / verify

**Benchmarking**
- Median timings (encap / decap / sign / verify / MAC)
- Ciphertext and signature sizes
- JSON export of results
- Optional E2E timing plot
- Benchmark results are shown as example measurements
- Exact timings may vary depending on hardware, system load and liboqs version

---

Everything is intentionally kept in one place.

---

**Design notes**
Supports multiple oqs-python API variants
(encap_secret, encapsulate, key import/export differences).
Explicit nonces prevent replay and bind sessions.
HKDF context separation is used.
Benchmarks are embedded to avoid wrapper overhead.
This is a measurement-oriented prototype, not production code.

**Background**
This prototype is derived from graduate-level research on
post-quantum authentication and protocol design and was extracted
into a standalone, reproducible form.
