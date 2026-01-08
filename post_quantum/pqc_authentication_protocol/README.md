Post-Quantum Authentication Prototype

This repository contains a reference implementation of a post-quantum
authentication protocol based on Kyber-512 (KEM + MAC) and
Dilithium-II (signature-based authentication).

The prototype is intended for research and performance evaluation.

Protocol overview





Performance evaluation

Benchmarks were executed on an x86-64 system (Intel i7-10750H,
Ubuntu 24.04 VM, Python 3.12, liboqs with AVX2 support).

Measured values include full protocol execution, including
object initialization, HKDF, MAC, and serialization.

Results (indicative)

Kyber-512 encapsulation: ~29 µs

Kyber-512 decapsulation: ~26 µs

Dilithium-II signing: ~68 µs

Dilithium-II verification: ~33 µs

The observed overhead is explained by object lifecycle management
and reflects realistic application-level usage.

Notes

Lower-level measurements (pure C calls) yield lower latency and are
consistent with published NIST reference values.
