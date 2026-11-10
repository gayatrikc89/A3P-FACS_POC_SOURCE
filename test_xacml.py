"""End-to-end tests of the XACML integration (Section 5.5, Figures 2-3)."""

import unittest
import xml.etree.ElementTree as ET

from privacy_interface import ResourceRecord
from system import build_system
from xacml_layer import (
    DENY,
    NOT_APPLICABLE,
    PC_ATTRIBUTE,
    PERMIT,
    SUBJECT_CAT,
    VERIFY_FUNCTION,
    Policy,
    RequestContext,
    Rule,
    policy_to_xacml,
)

TAU = "role:doctor AND (dept:icu OR dept:er)"


def make_system():
    system = build_system()
    record = ResourceRecord(
        "ehr-001",
        {"type": "medical-record", "owner-ward": "icu", "patient-name": "redacted", "dob": "1970-01-01"},
        {"location": "hospital-network", "time-window": "on-shift", "device": "ws-17"},
    )
    system.add_resource(record, sensitivity_index=2)
    system.add_policy(Policy(
        "ehr-read-policy", "ehr-001", frozenset({"read"}),
        (Rule("permit-clinician", "Permit", TAU,
              object_conditions=(("type", "medical-record"),),
              environment_conditions=(("location", "hospital-network"),)),),
    ))
    return system


class XacmlFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.system = make_system()
        cls.alice = cls.system.enrol_subject("alice", ["role:doctor", "dept:icu"])
        cls.bob = cls.system.enrol_subject("bob", ["role:nurse", "dept:icu"])

    def run_request(self, subject, object_id="ehr-001", op="read"):
        start = len(self.system.log.messages)
        result = self.system.pep.request_access(subject, object_id, op)
        return result, self.system.log.messages[start:]

    def test_permit_and_message_sequence(self):
        result, msgs = self.run_request(self.alice)
        self.assertTrue(result.granted)
        self.assertEqual(result.decision.decision, PERMIT)
        self.assertEqual([m.name for m in msgs], [
            "ReqGetAccess", "ReqGetAccess", "CheckRevocationList",
            "ReqFetchAttributes", "RespFetchAttributes",
            "ReqGetEvaluateAccess", "RespGetEvaluateAccess",
            "ReqShowCredential", "RespVerifyCredential", "RespVerifyCredential",
            "RespPolicyDecision", "AckRespVerifyCredential", "RespDecision",
            "EnforceAccessDecision",
        ])

    def test_unsatisfied_subject_denied(self):
        result, _ = self.run_request(self.bob)
        self.assertFalse(result.granted)
        self.assertEqual((result.decision.decision, result.decision.status), (DENY, "subject_authFail"))

    def test_wrong_operation_not_applicable(self):
        result, _ = self.run_request(self.alice, op="write")
        self.assertFalse(result.granted)
        self.assertEqual(result.decision.decision, NOT_APPLICABLE)

    def test_revoked_subject_denied_before_show(self):
        carol = self.system.enrol_subject("carol", ["role:doctor", "dept:er"])
        self.system.au.revoke(carol.key.public)
        result, msgs = self.run_request(carol)
        self.assertEqual((result.decision.decision, result.decision.status), (DENY, "revoked"))
        self.assertNotIn("ReqShowCredential", [m.name for m in msgs])

    def test_privacy_module_minimises_attributes(self):
        view = self.system.pip.fetch_attributes("ehr-001", "read")
        self.assertEqual(view.sensitivity_index, 2)
        self.assertEqual(set(view.object_attributes), {"type"})
        self.assertEqual(set(view.environment_attributes), {"location"})
        self.assertEqual(view.suppressed_count, 5)

    def test_request_context_has_no_plaintext_subject_attributes(self):
        ctx = RequestContext()
        ctx.attributes[SUBJECT_CAT] = {PC_ATTRIBUTE: {}, "a3p:session-message": 1}
        self.assertEqual(set(ctx.attributes[SUBJECT_CAT]), {PC_ATTRIBUTE, "a3p:session-message"})

    def test_policy_serialises_to_xacml(self):
        xml = policy_to_xacml(self.system.pap.policies[0])
        root = ET.fromstring(xml)
        self.assertTrue(root.tag.endswith("Policy"))
        self.assertIn(f'FunctionId="{VERIFY_FUNCTION}"', xml)
        self.assertIn(PC_ATTRIBUTE, xml)


if __name__ == "__main__":
    unittest.main()
