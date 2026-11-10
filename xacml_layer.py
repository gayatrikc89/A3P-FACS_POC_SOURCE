"""XACML / NIST ABAC integration layer of A3P-FACS (Section 5.5, Figures 2-3).

Components and their APIs (names follow Figure 2 of the manuscript):

    PEP             getAccessDecision(), enforceAccessDecision()
    ContextHandler  getAccessRequest(), requestSignature()
    PIP             fetchAttributes()            (uses the privacy-aware module)
    PAP             getEvaluateAccessRequest()
    PDP             getEvaluatePolicyDecision(), verifyCredential()

Anonymous credential verification is embedded in XACML rule evaluation as a
custom function ``a3p:verifyCredential`` (XACML 3.0 function extension point).
The presentation certificate PC replaces plaintext subject attributes in the
request context and is carried as attribute ``a3p:presentation-certificate``
of the access-subject category. Object and environment conditions are
evaluated with standard ``string-equal`` semantics over the attributes
released by the privacy-aware PIP. Policies and rules are combined with
deny-overrides.

Every interaction is recorded in a message log whose message names follow
Figure 3 (ReqGetAccess, ReqFetchAttributes, ReqGetEvaluateAccess,
RequestSignature / ReqShowCredential, RespVerifyCredential,
AckRespVerifyCredential, ...).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable
from xml.sax.saxutils import escape

from lsss import AccessStructure, build_access_structure
from privacy_interface import (
    PrivacyAwareModuleInterface,
    ReleasedAttributeView,
    ResourceRecord,
)
from protocol import (
    AttributeAuditor,
    IssuerPublicKey,
    PolicyNotSatisfied,
    PresentationCertificate,
    PublicParameters,
    Subject,
    verify_credential,
)

# XACML 3.0 identifiers
SUBJECT_CAT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
RESOURCE_CAT = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
ACTION_CAT = "urn:oasis:names:tc:xacml:3.0:attribute-category:action"
ENVIRONMENT_CAT = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment"
RESOURCE_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id"
ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id"
PC_ATTRIBUTE = "a3p:presentation-certificate"
MESSAGE_ATTRIBUTE = "a3p:session-message"
VERIFY_FUNCTION = "a3p:verifyCredential"
STRING_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:string-equal"
DENY_OVERRIDES = "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides"

PERMIT, DENY, NOT_APPLICABLE, INDETERMINATE = "Permit", "Deny", "NotApplicable", "Indeterminate"


# --------------------------------------------------------------------------
# Message log (Figure 3)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Message:
    sender: str
    receiver: str
    name: str
    detail: str = ""


@dataclass
class MessageLog:
    messages: list[Message] = field(default_factory=list)

    def send(self, sender: str, receiver: str, name: str, detail: str = "") -> None:
        self.messages.append(Message(sender, receiver, name, detail))

    def names(self) -> list[str]:
        return [m.name for m in self.messages]

    def as_mermaid(self) -> str:
        lines = ["sequenceDiagram"]
        for m in self.messages:
            text = m.name + (f"({m.detail})" if m.detail else "")
            lines.append(f"    {m.sender}->>{m.receiver}: {text}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Policy model (stored by the PAP)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    rule_id: str
    effect: str                                  # "Permit" or "Deny"
    subject_predicate: str | None = None         # tau, evaluated by a3p:verifyCredential
    object_conditions: tuple[tuple[str, str], ...] = ()
    environment_conditions: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Policy:
    policy_id: str
    target_resource: str                         # resource-id or "*"
    target_actions: frozenset[str]
    rules: tuple[Rule, ...]
    rule_combining: str = DENY_OVERRIDES

    def applies_to(self, object_id: str, op: str) -> bool:
        return self.target_resource in ("*", object_id) and op in self.target_actions

    def object_keys(self) -> frozenset[str]:
        return frozenset(k for r in self.rules for k, _ in r.object_conditions)

    def environment_keys(self) -> frozenset[str]:
        return frozenset(k for r in self.rules for k, _ in r.environment_conditions)

    def predicates(self) -> list[str]:
        out: list[str] = []
        for r in self.rules:
            if r.subject_predicate and r.subject_predicate not in out:
                out.append(r.subject_predicate)
        return out


def policy_to_xacml(policy: Policy) -> str:
    """Serialise a policy as XACML 3.0 XML (documentation / interoperability)."""
    out = [
        f'<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" '
        f'PolicyId="{escape(policy.policy_id)}" Version="1.0" RuleCombiningAlgId="{policy.rule_combining}">',
        "  <Target><AnyOf><AllOf>",
        f'    <Match MatchId="{STRING_EQUAL}"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">'
        f"{escape(policy.target_resource)}</AttributeValue>",
        f'      <AttributeDesignator Category="{RESOURCE_CAT}" AttributeId="{RESOURCE_ID}" '
        'DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="true"/></Match>',
        "  </AllOf></AnyOf></Target>",
    ]
    for rule in policy.rules:
        out.append(f'  <Rule RuleId="{escape(rule.rule_id)}" Effect="{rule.effect}">')
        out.append('    <Condition><Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:and">')
        if rule.subject_predicate:
            out += [
                f'      <Apply FunctionId="{VERIFY_FUNCTION}">',
                f'        <AttributeDesignator Category="{SUBJECT_CAT}" AttributeId="{PC_ATTRIBUTE}" '
                'DataType="a3p:pc" MustBePresent="true"/>',
                f'        <AttributeValue DataType="a3p:lsss-predicate">{escape(rule.subject_predicate)}</AttributeValue>',
                f'        <AttributeDesignator Category="{SUBJECT_CAT}" AttributeId="{MESSAGE_ATTRIBUTE}" '
                'DataType="http://www.w3.org/2001/XMLSchema#integer" MustBePresent="true"/>',
                "      </Apply>",
            ]
        for cat, conds in ((RESOURCE_CAT, rule.object_conditions), (ENVIRONMENT_CAT, rule.environment_conditions)):
            for key, value in conds:
                out += [
                    f'      <Apply FunctionId="{STRING_EQUAL}">',
                    f'        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{escape(value)}</AttributeValue>',
                    f'        <AttributeDesignator Category="{cat}" AttributeId="{escape(key)}" '
                    'DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="true"/>',
                    "      </Apply>",
                ]
        out.append("    </Apply></Condition>")
        out.append("  </Rule>")
    out.append("</Policy>")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Request context
# --------------------------------------------------------------------------

@dataclass
class RequestContext:
    attributes: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {SUBJECT_CAT: {}, RESOURCE_CAT: {}, ACTION_CAT: {}, ENVIRONMENT_CAT: {}}
    )

    def get(self, category: str, attribute_id: str) -> Any:
        return self.attributes.get(category, {}).get(attribute_id)

    def describe(self) -> dict[str, list[str]]:
        """Attribute ids per category (values omitted), e.g. for logs."""
        return {cat: sorted(vals) for cat, vals in self.attributes.items()}


# --------------------------------------------------------------------------
# PAP
# --------------------------------------------------------------------------

@dataclass
class PolicyAdministrationPoint:
    policies: list[Policy] = field(default_factory=list)
    _structures: dict[str, AccessStructure] = field(default_factory=dict)

    def add_policy(self, policy: Policy) -> None:
        self.policies.append(policy)
        for tau in policy.predicates():
            self._structures.setdefault(tau, build_access_structure(tau))

    def structure(self, tau: str) -> AccessStructure:
        return self._structures[tau]

    def applicable(self, object_id: str, op: str) -> list[Policy]:
        return [p for p in self.policies if p.applies_to(object_id, op)]

    def policy_attribute_keys(self, object_id: str, op: str) -> tuple[frozenset[str], frozenset[str]]:
        """Attribute designators used by applicable policies (needed by the privacy module)."""
        pols = self.applicable(object_id, op)
        return (
            frozenset().union(*(p.object_keys() for p in pols)) if pols else frozenset(),
            frozenset().union(*(p.environment_keys() for p in pols)) if pols else frozenset(),
        )

    def get_evaluate_access_request(
        self, object_id: str, view: ReleasedAttributeView, op: str
    ) -> tuple[list[Policy], list[str]]:
        """getEvaluateAccessRequest(object_id, oAtt, eAtt) -> applicable policies and predicate set {tau} (pai)."""
        policies = self.applicable(object_id, op)
        taus: list[str] = []
        for p in policies:
            for t in p.predicates():
                if t not in taus:
                    taus.append(t)
        return policies, taus


# --------------------------------------------------------------------------
# PIP
# --------------------------------------------------------------------------

class PolicyInformationPoint:
    def __init__(self, store: dict[str, ResourceRecord], privacy_module: PrivacyAwareModuleInterface,
                 pap: PolicyAdministrationPoint) -> None:
        self.store = store
        self.privacy_module = privacy_module
        self.pap = pap

    def fetch_attributes(self, object_id: str, op: str) -> ReleasedAttributeView | None:
        """fetchAttributes(object_id) -> minimised {oAtt}, {eAtt} (Section 5.6)."""
        record = self.store.get(object_id)
        if record is None:
            return None
        obj_keys, env_keys = self.pap.policy_attribute_keys(object_id, op)
        return self.privacy_module.minimise(record, obj_keys, env_keys)


# --------------------------------------------------------------------------
# PDP
# --------------------------------------------------------------------------

@dataclass
class Decision:
    decision: str
    status: str = "ok"
    credential_checks: dict[str, bool] = field(default_factory=dict)


class PolicyDecisionPoint:
    def __init__(self, pp: PublicParameters, aa_public: IssuerPublicKey, pap: PolicyAdministrationPoint) -> None:
        self.pp = pp
        self.aa_public = aa_public
        self.pap = pap
        # XACML function registry; a3p:verifyCredential is the A3P-FACS extension.
        self.functions: dict[str, Callable[..., bool]] = {
            VERIFY_FUNCTION: self.verify_credential,
            STRING_EQUAL: lambda a, b: a is not None and str(a) == str(b),
        }

    def verify_credential(self, pc: PresentationCertificate | None, tau: str, message: int | None) -> bool:
        """verifyCredential(pk_aa, PC, A_m, A_n, m, tau) -> {0,1}: Eq. (2)."""
        if pc is None or message is None:
            return False
        return verify_credential(self.pp, self.aa_public, pc, self.pap.structure(tau), message)

    def get_evaluate_policy_decision(self, ctx: RequestContext, policies: list[Policy]) -> Decision:
        """getEvaluatePolicyDecision(isPCVerified, oAtt, eAtt, op, tau) -> Permit/Deny/NotApplicable/Indeterminate."""
        checks: dict[str, bool] = {}   # memoised a3p:verifyCredential per tau (one check per predicate)
        object_id = ctx.get(RESOURCE_CAT, RESOURCE_ID)
        op = ctx.get(ACTION_CAT, ACTION_ID)
        results = []
        for policy in policies:
            if not policy.applies_to(object_id, op):
                continue
            results.append(self._combine([self._evaluate_rule(rule, ctx, checks) for rule in policy.rules]))
        decision = self._combine(results)
        status = "ok"
        if decision == NOT_APPLICABLE and checks and not any(checks.values()):
            decision, status = DENY, "subject_authFail"   # Algorithm 1: PC not verified
        return Decision(decision, status, checks)

    def _evaluate_rule(self, rule: Rule, ctx: RequestContext, checks: dict[str, bool]) -> str:
        if rule.subject_predicate:
            tau = rule.subject_predicate
            if tau not in checks:
                pcs = ctx.get(SUBJECT_CAT, PC_ATTRIBUTE) or {}
                checks[tau] = self.functions[VERIFY_FUNCTION](
                    pcs.get(tau), tau, ctx.get(SUBJECT_CAT, MESSAGE_ATTRIBUTE)
                )
            if not checks[tau]:
                return NOT_APPLICABLE
        for category, conditions in ((RESOURCE_CAT, rule.object_conditions), (ENVIRONMENT_CAT, rule.environment_conditions)):
            for key, value in conditions:
                actual = ctx.get(category, key)
                if actual is None:
                    return INDETERMINATE  # MustBePresent attribute missing (e.g. suppressed)
                if not self.functions[STRING_EQUAL](actual, value):
                    return NOT_APPLICABLE
        return rule.effect

    @staticmethod
    def _combine(decisions: list[str]) -> str:
        """deny-overrides."""
        if DENY in decisions:
            return DENY
        if INDETERMINATE in decisions:
            return INDETERMINATE
        if PERMIT in decisions:
            return PERMIT
        return NOT_APPLICABLE


# --------------------------------------------------------------------------
# Context handler
# --------------------------------------------------------------------------

class ContextHandler:
    def __init__(self, pip: PolicyInformationPoint, pap: PolicyAdministrationPoint, pdp: PolicyDecisionPoint,
                 auditor: AttributeAuditor, log: MessageLog) -> None:
        self.pip, self.pap, self.pdp, self.auditor, self.log = pip, pap, pdp, auditor, log

    def get_access_request(self, subject: Subject, object_id: str, op: str) -> Decision:
        """getAccessRequest(object_id, op): orchestrates the Resource Access Control Phase."""
        log = self.log
        # Revocation enforcement (Definition 4.6) before any credential is requested.
        log.send("ContextHandler", "AU", "CheckRevocationList", "pk_s")
        if self.auditor.is_revoked(subject.key.public.pk_s1):
            log.send("ContextHandler", "PEP", "RespDecision", "Deny: revoked")
            return Decision(DENY, "revoked")

        log.send("ContextHandler", "PIP", "ReqFetchAttributes", f"object_id={object_id}")
        view = self.pip.fetch_attributes(object_id, op)
        if view is None:
            log.send("PIP", "ContextHandler", "RespFetchAttributes", "unknown object")
            return Decision(NOT_APPLICABLE, "unknown_object")
        log.send("PIP", "ContextHandler", "RespFetchAttributes",
                 f"{{oAtt}}={len(view.object_attributes)}, {{eAtt}}={len(view.environment_attributes)}, SI={view.sensitivity_index}")

        log.send("ContextHandler", "PAP", "ReqGetEvaluateAccess", "object_id, {oAtt}, {eAtt}")
        policies, taus = self.pap.get_evaluate_access_request(object_id, view, op)
        log.send("PAP", "ContextHandler", "RespGetEvaluateAccess", f"pai={taus}")
        if not policies:
            log.send("ContextHandler", "PEP", "RespDecision", NOT_APPLICABLE)
            return Decision(NOT_APPLICABLE, "no_applicable_policy")

        message = secrets.randbelow(2**128)  # fresh per session (anti-replay challenge m)
        pcs = self.request_signature(subject, taus, message)

        ctx = RequestContext()
        ctx.attributes[SUBJECT_CAT] = {PC_ATTRIBUTE: pcs, MESSAGE_ATTRIBUTE: message}
        ctx.attributes[RESOURCE_CAT] = {RESOURCE_ID: object_id, **view.object_attributes}
        ctx.attributes[ACTION_CAT] = {ACTION_ID: op}
        ctx.attributes[ENVIRONMENT_CAT] = dict(view.environment_attributes)

        log.send("ContextHandler", "PDP", "RespVerifyCredential", "PC (request context)")
        decision = self.pdp.get_evaluate_policy_decision(ctx, policies)
        result = "Success" if decision.credential_checks and all(decision.credential_checks.values()) else "Fail"
        log.send("PDP", "ContextHandler", "RespPolicyDecision", decision.decision)
        log.send("ContextHandler", "Subject", "AckRespVerifyCredential", f"result={result}")
        log.send("ContextHandler", "PEP", "RespDecision", decision.decision)
        return decision

    def request_signature(self, subject: Subject, taus: list[str], message: int) -> dict[str, PresentationCertificate]:
        """requestSignature(tau, m): ask the subject for one PC per predicate."""
        pcs: dict[str, PresentationCertificate] = {}
        for tau in taus:
            self.log.send("ContextHandler", "Subject", "ReqShowCredential", f"predicate={tau!r}, message=m")
            try:
                pcs[tau] = subject.show_credential(self.pap.structure(tau), message)
                self.log.send("Subject", "ContextHandler", "RespVerifyCredential",
                              "PC=(omega,S1,S2,C1',C2',A_m,A_n)")
            except PolicyNotSatisfied:
                self.log.send("Subject", "ContextHandler", "RespVerifyCredential", "no PC (predicate not satisfied)")
        return pcs


# --------------------------------------------------------------------------
# PEP
# --------------------------------------------------------------------------

@dataclass
class AccessResult:
    granted: bool
    decision: Decision


class PolicyEnforcementPoint:
    def __init__(self, context_handler: ContextHandler, log: MessageLog) -> None:
        self.context_handler = context_handler
        self.log = log

    def get_access_decision(self, subject: Subject, object_id: str, op: str) -> Decision:
        """getAccessDecision(): forwards ReqGetAccess to the context handler."""
        self.log.send("Subject", "PEP", "ReqGetAccess", f"objectId={object_id}, op={op}")
        self.log.send("PEP", "ContextHandler", "ReqGetAccess", f"objectId={object_id}, op={op}")
        return self.context_handler.get_access_request(subject, object_id, op)

    def enforce_access_decision(self, decision: Decision) -> AccessResult:
        """enforceAccessDecision(): only Permit grants access (deny-biased PEP)."""
        granted = decision.decision == PERMIT
        self.log.send("PEP", "Subject", "EnforceAccessDecision", "granted" if granted else "denied")
        return AccessResult(granted, decision)

    def request_access(self, subject: Subject, object_id: str, op: str) -> AccessResult:
        return self.enforce_access_decision(self.get_access_decision(subject, object_id, op))
