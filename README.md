# A3P-FACS: Proof-of-Concept Implementation (revised manuscript, R2 with unlinkability fix)

Reference implementation of **A3P-FACS: Anonymous Attribute-based Authentication with Privacy Preserving Approach for Fine-grained Access Control System**. It covers:

- **Anonymous credential layer** (`protocol.py`, `lsss.py`): paramSetup, keyGeneration, issueCredential/obtainCredential (Eq. 1), showCredential with general AND/OR LSSS policies, verifyCredential (Eq. 2), traceCredential/judgeCredential (Eq. 3), and the revocation list.
- **NIST ABAC / XACML layer** (`xacml_layer.py`): PEP, context handler, PIP, PAP and PDP. Anonymous credential verification is embedded in XACML rule evaluation through the custom function `a3p:verifyCredential`.
- **Privacy-aware module interface** (`privacy_interface.py`): sensitivity-index-based (non-cryptographic) minimisation of object and environment attributes.
- **System wiring** (`system.py`) and an end-to-end demo (`demo.py`).

**See [`API_XACML.md`](API_XACML.md)** for the component APIs, data types, Figure 3 message sequence charts, the XACML request context and policy, and the decision logic.

## Run

```bash
pip install -r requirements.txt
python -m unittest -v                  # 16 tests
python demo.py                         # message trace + XACML policy
python benchmark.py --repetitions 5    # writes benchmark_results.json
```

## Parameters

| Item | Value |
|---|---|
| Pairing | Type-3, BLS12-381 (381-bit base field, 255-bit prime-order subgroups, ≈128-bit security) |
| Hash | SHA-256; attributes hashed to G1 with `BLS12381G1_XMD:SHA-256_SSWU_RO_` (RFC 9380) |
| Library | `py_ecc` 8.0.0 (pure Python, unaudited, not constant-time; research use only) |

## Files

| File | Content |
|---|---|
| `protocol.py` | KGC, AA, Subject, AU; Eq. (1)–(3) |
| `lsss.py` | policy parser, Lewko–Waters LSSS matrix, reconstruction vector |
| `xacml_layer.py` | PEP, context handler, PIP, PAP, PDP, request context, XACML export, message log |
| `privacy_interface.py` | privacy policy manager (SI labels) and privacy-aware module interface |
| `system.py` | builds a complete deployment |
| `demo.py` | runs one session and prints the Figure 3 trace and the XACML policy |
| `test_protocol.py`, `test_xacml.py` | unit and end-to-end tests |
| `benchmark.py`, `benchmark_results.json`, `BenchmarkAnalysis.md` | phase-wise performance |
| `API_XACML.md` | API and XACML integration specification |
