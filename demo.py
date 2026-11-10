"""Runs one complete A3P-FACS session and prints the Figure 3 message trace,
the request-context categories and the stored XACML policy."""

from test_xacml import make_system
from xacml_layer import policy_to_xacml


def main() -> None:
    system = make_system()
    alice = system.enrol_subject("alice", ["role:doctor", "dept:icu"])
    bob = system.enrol_subject("bob", ["role:nurse", "dept:icu"])
    for subject in (alice, bob):
        result = system.pep.request_access(subject, "ehr-001", "read")
        print(f"{subject.subject_id}: {result.decision.decision} ({result.decision.status}), granted={result.granted}")
    print("\n--- Message trace (mermaid) ---")
    print(system.log.as_mermaid())
    print("\n--- XACML policy ---")
    print(policy_to_xacml(system.pap.policies[0]))
    pc = alice.show_credential(system.pap.structure(system.pap.policies[0].rules[0].subject_predicate), 1)
    traced = system.au.identify(pc, system.aa)
    print(f"\nAU traceCredential/judgeCredential identifies: {traced}")


if __name__ == "__main__":
    main()
