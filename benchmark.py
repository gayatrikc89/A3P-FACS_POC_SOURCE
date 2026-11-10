"""Phase-wise benchmarks of the A3P-FACS reference implementation (R2)."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from importlib.metadata import version
from pathlib import Path
from typing import Any, Callable

from py_ecc import optimized_bls12_381 as bls

from lsss import build_access_structure
from privacy_interface import (
    PrivacyAwareModuleInterface,
    PrivacyPolicyManager,
    synthetic_resource,
)
from protocol import AttributeAuditor, AttributeAuthority, KeyGenerationCenter, Subject, verify_credential, verify_equation_1
from test_xacml import make_system

POLICIES = {
    1: "role:doctor",
    3: "role:doctor AND (dept:icu OR dept:er)",
    5: "role:doctor AND (dept:icu OR dept:er) AND (shift:day OR shift:night)",
}
SUBJECT_ATTRS = ["role:doctor", "dept:icu", "shift:day"]


def measure(fn: Callable[[], Any], repetitions: int, inner: int = 1) -> dict[str, float]:
    fn()  # warm-up
    samples = []
    for _ in range(repetitions):
        t = time.perf_counter_ns()
        for _ in range(inner):
            fn()
        samples.append((time.perf_counter_ns() - t) / 1e6 / inner)
    return {"median_ms": statistics.median(samples), "min_ms": min(samples),
            "max_ms": max(samples), "mean_ms": statistics.fmean(samples), "repetitions": repetitions}


def run(repetitions: int, privacy_inner: int) -> dict[str, Any]:
    kgc = KeyGenerationCenter()
    pp, msk = kgc.param_setup()
    aa = AttributeAuthority(pp, kgc.key_generation_aa(pp))
    au = AttributeAuditor(msk, aa.public)
    key = kgc.key_generation_subject()
    subject = Subject("s", pp, key)
    cc = aa.issue_credential("s", key.public, SUBJECT_ATTRS)
    assert subject.obtain_credential(cc, SUBJECT_ATTRS, aa.public)

    timings: dict[str, Any] = {
        "system_initialization/paramSetup": measure(kgc.param_setup, repetitions),
        "access_credential_setup/keyGeneration_subject": measure(kgc.key_generation_subject, repetitions),
        "access_credential_setup/keyGeneration_aa": measure(lambda: kgc.key_generation_aa(pp), repetitions),
        "access_credential_setup/issueCredential_3_attributes": measure(
            lambda: aa.issue_credential("tmp", key.public, SUBJECT_ATTRS), repetitions),
        "access_credential_setup/obtainCredential_eq1": measure(
            lambda: verify_equation_1(pp, aa.public, key.public, cc, SUBJECT_ATTRS), repetitions),
    }
    validation: dict[str, Any] = {"eq1_honest": verify_equation_1(pp, aa.public, key.public, cc, SUBJECT_ATTRS)}
    for rows, tau in POLICIES.items():
        s = build_access_structure(tau)
        assert s.rows == rows
        pc = subject.show_credential(s, 42)
        timings[f"anonymous_verifying/showCredential_{rows}_rows"] = measure(lambda s=s: subject.show_credential(s, 42), repetitions)
        timings[f"anonymous_verifying/verifyCredential_eq2_{rows}_rows"] = measure(
            lambda s=s, pc=pc: verify_credential(pp, aa.public, pc, s, 42), repetitions)
        validation[f"eq2_honest_{rows}_rows"] = verify_credential(pp, aa.public, pc, s, 42)
        validation[f"eq2_wrong_message_{rows}_rows"] = verify_credential(pp, aa.public, pc, s, 43)
    pc = subject.show_credential(build_access_structure(POLICIES[3]), 42)
    beta = au.trace_credential(pc)
    timings["inspection/traceCredential"] = measure(lambda: au.trace_credential(pc), repetitions)
    timings["inspection/judgeCredential_eq3"] = measure(lambda: au.judge_credential(beta, aa.registry["s"]), repetitions)
    validation["eq3_honest"] = au.judge_credential(beta, aa.registry["s"])

    system = make_system()
    alice = system.enrol_subject("alice", ["role:doctor", "dept:icu"])
    timings["resource_access_control/end_to_end_xacml_request"] = measure(
        lambda: system.pep.request_access(alice, "ehr-001", "read"), repetitions)
    validation["end_to_end_decision"] = system.pep.request_access(alice, "ehr-001", "read").decision.decision

    pip_results = {}
    manager = PrivacyPolicyManager()
    module = PrivacyAwareModuleInterface(manager)
    obj_keys = frozenset(f"oatt_{i:04d}" for i in range(5))
    env_keys = frozenset(f"eatt_{i:04d}" for i in range(3))
    for n_obj, n_env in ((25, 10), (100, 25), (500, 50)):
        record = synthetic_resource(n_obj, n_env)
        for si in (0, 1, 2):
            manager.label(record.object_id, si)
            view = module.minimise(record, obj_keys, env_keys)
            pip_results[f"object_{n_obj}_environment_{n_env}_si_{si}"] = {
                "released": view.released_count, "suppressed": view.suppressed_count,
                "release_ratio": round(view.release_ratio, 4),
                "fetchAttributes": measure(lambda r=record: module.minimise(r, obj_keys, env_keys), repetitions, privacy_inner),
            }

    return {
        "artifact": "A3P-FACS reference implementation (revised manuscript R2)",
        "environment": {"os": platform.platform(), "processor": platform.processor(),
                        "python": sys.version.split()[0], "py_ecc": version("py-ecc")},
        "parameters": {"curve": "BLS12-381 (Type-3)", "base_field_bits": bls.field_modulus.bit_length(),
                       "subgroup_order_bits": bls.curve_order.bit_length(), "hash": "SHA-256",
                       "hash_to_curve": "BLS12381G1_XMD:SHA-256_SSWU_RO_", "subject_attributes": len(SUBJECT_ATTRS)},
        "timings": timings,
        "privacy_aware_pip": pip_results,
        "validation": validation,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--privacy-inner-iterations", type=int, default=500)
    parser.add_argument("--output", type=Path, default=Path("benchmark_results.json"))
    args = parser.parse_args()
    result = run(args.repetitions, args.privacy_inner_iterations)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for name, t in result["timings"].items():
        print(f"{name:60s} {t['median_ms']:10.2f} ms")
    print(json.dumps(result["validation"], indent=2))


if __name__ == "__main__":
    main()
