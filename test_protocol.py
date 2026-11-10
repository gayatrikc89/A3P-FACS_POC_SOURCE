"""Correctness tests for the anonymous credential layer (Eq. (1)-(3), LSSS)."""

import dataclasses
import unittest

from lsss import build_access_structure, is_reconstruction_valid, reconstruction_vector
from protocol import (
    AttributeAuditor,
    AttributeAuthority,
    Credential,
    KeyGenerationCenter,
    PolicyNotSatisfied,
    PresentationCertificate,
    Subject,
    build_presentation,
    verify_credential,
    verify_equation_1,
)

POLICY = "role:doctor AND (dept:icu OR dept:er)"


class LsssTests(unittest.TestCase):
    def test_reconstruction(self):
        s = build_access_structure(POLICY)
        self.assertEqual(s.row_labels, ("role:doctor", "dept:icu", "dept:er"))
        for attrs in (["role:doctor", "dept:icu"], ["role:doctor", "dept:er", "x"]):
            nu = reconstruction_vector(s, attrs)
            self.assertIsNotNone(nu)
            self.assertTrue(is_reconstruction_valid(s, nu))
        self.assertIsNone(reconstruction_vector(s, ["role:doctor"]))
        self.assertIsNone(reconstruction_vector(s, ["dept:icu", "dept:er"]))

    def test_nested_policy(self):
        s = build_access_structure("(a AND b) OR (c AND (d OR e))")
        self.assertIsNotNone(reconstruction_vector(s, ["c", "e"]))
        self.assertIsNone(reconstruction_vector(s, ["a", "c"]))


class CredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kgc = KeyGenerationCenter()
        cls.pp, cls.msk = cls.kgc.param_setup()
        cls.aa = AttributeAuthority(cls.pp, cls.kgc.key_generation_aa(cls.pp))
        cls.au = AttributeAuditor(cls.msk, cls.aa.public)
        cls.structure = build_access_structure(POLICY)

    def enrol(self, sid, attrs):
        key = self.kgc.key_generation_subject()
        subject = Subject(sid, self.pp, key)
        cc = self.aa.issue_credential(sid, key.public, attrs)
        self.assertTrue(subject.obtain_credential(cc, attrs, self.aa.public))
        return subject

    def test_equation_1(self):
        s = self.enrol("alice", ["role:doctor", "dept:icu"])
        self.assertTrue(verify_equation_1(self.pp, self.aa.public, s.key.public, s.credential, s.attributes))
        # a credential checked against a different attribute set is rejected
        self.assertFalse(verify_equation_1(self.pp, self.aa.public, s.key.public, s.credential, ["role:nurse"]))

    def test_equation_2_honest_and_wrong_message(self):
        s = self.enrol("bob", ["role:doctor", "dept:er", "hospital:a"])
        pc = s.show_credential(self.structure, 1234)
        self.assertTrue(verify_credential(self.pp, self.aa.public, pc, self.structure, 1234))
        self.assertFalse(verify_credential(self.pp, self.aa.public, pc, self.structure, 9999))

    def test_presentation_carries_no_attributes(self):
        fields = {f.name for f in dataclasses.fields(PresentationCertificate)}
        self.assertEqual(fields, {"omega", "s1", "s2", "c1_prime", "c2_prime", "a_m", "a_n"})

    def test_unsatisfied_policy(self):
        s = self.enrol("carol", ["role:doctor", "hospital:a"])
        with self.assertRaises(PolicyNotSatisfied):
            s.show_credential(self.structure, 1)
        # Forcing a presentation with an invalid vector nu fails Eq. (2) (policy binding).
        forced = build_presentation(self.pp, s.key, s.credential, s.attributes, self.structure, (1, 0, 0), 1)
        self.assertFalse(verify_credential(self.pp, self.aa.public, forced, self.structure, 1))

    def test_collusion_rejected(self):
        a = self.enrol("dave", ["role:doctor"])
        b = self.enrol("erin", ["dept:icu"])
        merged = Credential(a.credential.c1, a.credential.c2, a.credential.c3,
                            {**a.credential.c_u, **b.credential.c_u})
        nu = reconstruction_vector(self.structure, ["role:doctor", "dept:icu"])
        pc = build_presentation(self.pp, a.key, merged, ("role:doctor", "dept:icu"), self.structure, nu, 7)
        self.assertFalse(verify_credential(self.pp, self.aa.public, pc, self.structure, 7))

    def test_unlinkability_of_presentations(self):
        from protocol import pair
        from py_ecc import optimized_bls12_381 as bls
        s = self.enrol("henry", ["role:doctor", "dept:icu"])
        p1 = s.show_credential(self.structure, 11)
        p2 = s.show_credential(self.structure, 22)
        self.assertNotEqual(pair(p1.a_m, p1.a_n), pair(p2.a_m, p2.a_n))   # e(A_m, A_n) differs per session
        for name in ("s1", "s2", "c1_prime", "c2_prime", "a_m", "a_n"):
            self.assertFalse(bls.eq(getattr(p1, name), getattr(p2, name)))
        self.assertFalse(hasattr(self.pp, "mpk2"))  # mpk2 is not public

    def test_trace_and_judge_equation_3(self):
        s = self.enrol("frank", ["role:doctor", "dept:icu"])
        self.enrol("grace", ["role:doctor", "dept:icu"])
        pc = s.show_credential(self.structure, 55)
        beta = self.au.trace_credential(pc)
        self.assertTrue(self.au.judge_credential(beta, self.aa.registry["frank"]))
        self.assertFalse(self.au.judge_credential(beta, self.aa.registry["grace"]))
        self.assertEqual(self.au.identify(pc, self.aa), "frank")


if __name__ == "__main__":
    unittest.main()
