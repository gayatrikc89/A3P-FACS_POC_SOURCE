# Benchmark Analysis 

Results in `benchmark_results.json` were produced by `python benchmark.py --repetitions 3` with this environment:

- OS: `Linux-6.18.44-fc-v310-x86_64-with-glibc2.39`; Python 3.13.18; py_ecc 8.0.0
- Hardware: 2-vCPU Intel Xeon cloud VM 

**Re-run `benchmark.py` on the machine described in Section 8 of the manuscript before quoting any numbers in the paper.**

## Phase-wise latency

| Operation | Median (ms) | Min (ms) | Max (ms) |
|---|---:|---:|---:|
| System initialization: paramSetup | 21.7 | 21.1 | 22.1 |
| Credential setup: keyGeneration (subject) | 248.0 | 245.9 | 248.1 |
| Credential setup: keyGeneration (AA) | 266.5 | 263.1 | 308.0 |
| Credential setup: issueCredential (3 attributes) | 42.5 | 41.0 | 42.7 |
| Credential setup: obtainCredential, Eq. (1) | 726.7 | 725.2 | 731.2 |
| Verifying: showCredential, 1-row policy | 63.8 | 63.3 | 65.2 |
| Verifying: verifyCredential Eq. (2), 1-row policy | 960.3 | 959.0 | 964.6 |
| Verifying: showCredential, 3-row policy | 69.3 | 68.5 | 70.4 |
| Verifying: verifyCredential Eq. (2), 3-row policy | 1208.2 | 1206.1 | 1209.9 |
| Verifying: showCredential, 5-row policy | 71.8 | 71.7 | 72.1 |
| Verifying: verifyCredential Eq. (2), 5-row policy | 1455.0 | 1449.5 | 1457.4 |
| Inspection: traceCredential | 4.1 | 4.1 | 4.1 |
| Inspection: judgeCredential, Eq. (3) | 487.2 | 486.8 | 488.7 |
| Resource access control: end-to-end XACML request (3-row policy) | 1275.9 | 1275.5 | 1289.4 |

Verification cost grows by about one pairing per used LSSS row; showCredential is dominated by scalar multiplications.

## Privacy-aware PIP (attribute minimisation)

| Resource (object / environment attributes) | SI | Released | Suppressed | Release ratio | fetchAttributes (µs) |
|---|---:|---:|---:|---:|---:|
| 25 / 10 | 0 | 35 | 0 | 1.000 | 3.6 |
| 25 / 10 | 1 | 15 | 20 | 0.429 | 2.0 |
| 25 / 10 | 2 | 8 | 27 | 0.229 | 1.5 |
| 100 / 25 | 0 | 125 | 0 | 1.000 | 11.0 |
| 100 / 25 | 1 | 30 | 95 | 0.240 | 3.2 |
| 100 / 25 | 2 | 8 | 117 | 0.064 | 1.5 |
| 500 / 50 | 0 | 550 | 0 | 1.000 | 64.5 |
| 500 / 50 | 1 | 55 | 495 | 0.100 | 5.3 |
| 500 / 50 | 2 | 8 | 542 | 0.015 | 1.6 |

## Validation

| Check | Result |
|---|---|
| eq1_honest | True |
| eq2_honest_1_rows | True |
| eq2_wrong_message_1_rows | False |
| eq2_honest_3_rows | True |
| eq2_wrong_message_3_rows | False |
| eq2_honest_5_rows | True |
| eq2_wrong_message_5_rows | False |
| eq3_honest | True |
| end_to_end_decision | Permit |
