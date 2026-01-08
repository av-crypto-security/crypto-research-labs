# PQC Authentication Prototype (KEM+MAC & Signature-Based)

Minimal, self-contained prototype demonstrating **post-quantum authentication primitives**
based on **KEM + MAC** and **digital signatures**, implemented with `oqs-python`
(liboqs bindings).

The goal of this repository is to provide a **clear, reproducible reference**
for:
- PQC-based authenticated key establishment
- Signature-based authentication
- Practical performance benchmarking (latency, sizes)
- Robust interaction with different `oqs-python` API variants

This is **not a full protocol implementation**, but a focused cryptographic prototype.

---

## Features

### Implemented primitives
- **KEM**: Kyber (default: `Kyber512`)
- **Signature**: Dilithium (default: `Dilithium2`)
- **MAC**: HMAC-SHA256
- **Key derivation**: HKDF (RFC 5869–style)

### Authentication models
- **KEM + MAC**
  - Nonce-based context binding
  - Shared secret derivation via HKDF
  - Explicit MAC verification
- **Signature-based authentication**
  - Nonce-based challenge-response
  - Explicit sign / verify separation

### Benchmarking
- Median timing measurements
- Encapsulation / decapsulation
- Signing / verification
- MAC generation / verification
- Ciphertext and signature sizes
- JSON export of results
- Optional matplotlib visualization

---

## Repository structure

```text
.
├── pqc_prototype.py     # Single-file prototype (protocol + benchmarks)
├── pqc_summary.json     # Auto-generated benchmark results
├── pqc_plot.png         # Auto-generated E2E timing plot (optional)
├── protocol_diagram.png # High-level protocol flow (optional)
└── README.md
