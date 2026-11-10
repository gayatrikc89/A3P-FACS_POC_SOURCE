"""Wires all A3P-FACS entities together (System Initialization -> Resource Access Control)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from privacy_interface import PrivacyAwareModuleInterface, PrivacyPolicyManager, ResourceRecord
from protocol import (
    AttributeAuditor,
    AttributeAuthority,
    KeyGenerationCenter,
    PublicParameters,
    Subject,
)
from xacml_layer import (
    ContextHandler,
    MessageLog,
    Policy,
    PolicyAdministrationPoint,
    PolicyDecisionPoint,
    PolicyEnforcementPoint,
    PolicyInformationPoint,
)


@dataclass
class A3PFACSSystem:
    pp: PublicParameters
    kgc: KeyGenerationCenter
    aa: AttributeAuthority
    au: AttributeAuditor
    pap: PolicyAdministrationPoint
    pip: PolicyInformationPoint
    pdp: PolicyDecisionPoint
    context_handler: ContextHandler
    pep: PolicyEnforcementPoint
    privacy_manager: PrivacyPolicyManager
    store: dict[str, ResourceRecord]
    log: MessageLog

    def enrol_subject(self, subject_id: str, attributes: Iterable[str]) -> Subject:
        """Access Credential Setup Phase: keyGeneration -> issueCredential -> obtainCredential."""
        self.log.send("Subject", "KGC", "ReqKeyGen", 'type="S"')
        key = self.kgc.key_generation_subject()
        self.log.send("KGC", "Subject", "RespKeyGen", "pk_s, sk_s")
        subject = Subject(subject_id, self.pp, key)
        self.log.send("Subject", "AA", "ReqIssueCredential", "pk_s")
        cc = self.aa.issue_credential(subject_id, key.public, attributes)
        self.log.send("AA", "Subject", "RespObtainCredential", "CC=(C1,C2,C3,C_u)")
        if not subject.obtain_credential(cc, attributes, self.aa.public):
            raise RuntimeError("credential rejected by Eq. (1)")
        return subject

    def add_resource(self, record: ResourceRecord, sensitivity_index: int) -> None:
        self.store[record.object_id] = record
        self.privacy_manager.label(record.object_id, sensitivity_index)

    def add_policy(self, policy: Policy) -> None:
        self.pap.add_policy(policy)


def build_system() -> A3PFACSSystem:
    log = MessageLog()
    kgc = KeyGenerationCenter()
    log.send("KGC", "KGC", "paramSetup", "pp")
    pp, msk = kgc.param_setup()
    log.send("AA", "KGC", "KeyGen", 'type="aa"')
    aa = AttributeAuthority(pp, kgc.key_generation_aa(pp))
    log.send("KGC", "AU", "RespKeyGen", "(mpk, msk)")
    au = AttributeAuditor(msk, aa.public)
    pap = PolicyAdministrationPoint()
    privacy_manager = PrivacyPolicyManager()
    store: dict[str, ResourceRecord] = {}
    pip = PolicyInformationPoint(store, PrivacyAwareModuleInterface(privacy_manager), pap)
    pdp = PolicyDecisionPoint(pp, aa.public, pap)
    ch = ContextHandler(pip, pap, pdp, au, log)
    pep = PolicyEnforcementPoint(ch, log)
    return A3PFACSSystem(pp, kgc, aa, au, pap, pip, pdp, ch, pep, privacy_manager, store, log)
