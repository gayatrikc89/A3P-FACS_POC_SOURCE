"""Anonymous attribute-based credential system of A3P-FACS (Sections 5.1-5.4).

Reference implementation of the revised (R2) manuscript, with the unlinkability fix on BLS12-381
(py_ecc). Group operations are written additively: "g^a" in the paper is
``multiply(G, a)`` and "x * y" in G1/G2 is ``add(x, y)``.

Entities and algorithms follow Figure 2 (Implementation Model):

    KGC      : paramSetup(), keyGeneration()
    AA       : issueCredential()
    Subject  : obtainCredential()   -> Eq. (1)
               showCredential()     -> presentation certificate PC
    PDP      : verifyCredential()   -> Eq. (2)
    AU       : traceCredential(), judgeCredential() -> Eq. (3)

Verification equations implemented (revised manuscript):

    Eq. (1)  e(C1,g2) = pk_aa1 * e(pk_s1^{1/H(sAtt)}, g2) * e(mpk1, C3)
    Eq. (2)  e(S1,g2) = pk_aa1 * e(A_m, A_n)
                        * prod_i e(U_{p(i)} * mpk1^{rho_i}, w_i) * e(S2, g2^m)
    Eq. (3)  e(beta*, g2) * pk_aa1^{-1} = e(pk_s1^{1/H(sAtt)}, g2)

with H(sAtt) = prod_{att in sAtt} H(att) mod p and H(att) = H2(H1(att)).

Unlinkability fix: in showCredential() the subject adds a fresh delta to S1 and
to A_n, so e(A_m, A_n) = e(g1,g2)^{sk_s/H(sAtt) + delta} differs in every
session, and blinds the tracing pair (C1', C2') with an independent r''.
mpk2 = g2^{-alpha} is kept by the AU and is not published.

This is a research prototype (py_ecc is unaudited and not constant time).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable

from py_ecc import optimized_bls12_381 as bls
from py_ecc.bls.hash_to_curve import hash_to_G1

from lsss import AccessStructure, reconstruction_vector

Scalar = int
Point = Any
Target = Any

P = bls.curve_order
ATTRIBUTE_DST = b"A3P-FACS-ATTRIBUTE-BLS12381G1_XMD:SHA-256_SSWU_RO_"


class PolicyNotSatisfied(Exception):
    """Raised by showCredential() when tau(sAtt) = 0."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def random_scalar() -> Scalar:
    return secrets.randbelow(P - 1) + 1


def _inv(x: Scalar) -> Scalar:
    x %= P
    if x == 0:
        raise ValueError("cannot invert zero")
    return pow(x, -1, P)


def pair(g1_point: Point, g2_point: Point) -> Target:
    """e: G1 x G2 -> GT."""
    return bls.pairing(g2_point, g1_point)


def _is_inf(point: Point) -> bool:
    return bls.is_inf(point)


@lru_cache(maxsize=4096)
def H1(attribute: str) -> Point:
    """H1: {0,1}* -> G1 (RFC 9380 hash-to-curve). Also the universal attribute element U_att."""
    return hash_to_G1(attribute.encode("utf-8"), ATTRIBUTE_DST, hashlib.sha256)


def H2(point: Point) -> Scalar:
    """H2: G1 -> Z_p^* (SHA-256 of the affine encoding)."""
    x, y = bls.normalize(point)
    data = int(x.n).to_bytes(48, "big") + int(y.n).to_bytes(48, "big")
    value = int.from_bytes(hashlib.sha256(data).digest(), "big") % P
    return value or 1


def H_att(attribute: str) -> Scalar:
    return H2(H1(attribute))


def H_set(attributes: Iterable[str]) -> Scalar:
    """Aggregated hash H(sAtt) = prod H(att) mod p (product over the empty set is 1)."""
    result = 1
    for attribute in sorted(set(attributes)):
        result = (result * H_att(attribute)) % P
    return result


# --------------------------------------------------------------------------
# keys and data objects
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicParameters:
    """pp = (G1, G2, GT, e, mpk, g1, g2, U, H1, H2). Contains NO secrets."""

    mpk1: Point  # g1^alpha   (mpk2 = g2^{-alpha} is kept by the AU and not published)


@dataclass(frozen=True)
class AuditorKey:
    """msk = alpha, held only by the attribute auditor (AU)."""

    alpha: Scalar
    mpk2: Point  # g2^{-alpha}, private to the AU


@dataclass(frozen=True)
class IssuerPublicKey:
    pk_aa1: Target  # e(g1,g2)^{sk_aa1}
    pk_aa2: Point   # mpk2^{sk_aa1}


@dataclass(frozen=True)
class IssuerKey:
    sk_aa1: Scalar
    sk_aa2: Point  # g1^{sk_aa1}
    public: IssuerPublicKey


@dataclass(frozen=True)
class SubjectPublicKey:
    pk_s1: Point   # g1^{sk_s}
    pk_s2: Target  # e(g1,g2)^{sk_s}


@dataclass(frozen=True)
class SubjectKey:
    sk_s: Scalar
    public: SubjectPublicKey


@dataclass(frozen=True)
class Credential:
    """CC = {C1, C2, C3, C_u}. Held privately by the subject together with sAtt."""

    c1: Point
    c2: Point
    c3: Point
    c_u: dict[str, Point]


@dataclass(frozen=True)
class PresentationCertificate:
    """PC = (Omega, S1, S2, C1', C2', A_m, A_n).

    Omega = (w_1, ..., w_l), one G2 element per row of the LSSS matrix.
    The PC carries NO attribute names or values.
    """

    omega: tuple[Point, ...]
    s1: Point
    s2: Point
    c1_prime: Point
    c2_prime: Point
    a_m: Point
    a_n: Point


# --------------------------------------------------------------------------
# KGC: System Initialization Phase and key generation (Sections 5.1, 5.2)
# --------------------------------------------------------------------------

class KeyGenerationCenter:
    def param_setup(self) -> tuple[PublicParameters, AuditorKey]:
        """paramSetup(k) -> pp; also outputs msk = alpha for the AU."""
        alpha = random_scalar()
        mpk2 = bls.multiply(bls.G2, (-alpha) % P)
        self._mpk2 = mpk2
        pp = PublicParameters(mpk1=bls.multiply(bls.G1, alpha))
        return pp, AuditorKey(alpha, mpk2)

    def key_generation_subject(self) -> SubjectKey:
        sk = random_scalar()
        pk1 = bls.multiply(bls.G1, sk)
        return SubjectKey(sk, SubjectPublicKey(pk1, pair(pk1, bls.G2)))

    def key_generation_aa(self, pp: PublicParameters) -> IssuerKey:
        sk1 = random_scalar()
        sk2 = bls.multiply(bls.G1, sk1)
        return IssuerKey(sk1, sk2, IssuerPublicKey(pair(sk2, bls.G2), bls.multiply(self._mpk2, sk1)))


# --------------------------------------------------------------------------
# AA: issueCredential() (Section 5.2)
# --------------------------------------------------------------------------

@dataclass
class IssuanceRecord:
    pk_s1: Point
    h_satt: Scalar


class AttributeAuthority:
    def __init__(self, pp: PublicParameters, key: IssuerKey) -> None:
        self.pp = pp
        self.key = key
        # Issuance log shared with the AU for judgeCredential() (Section 5.4).
        self.registry: dict[str, IssuanceRecord] = {}

    @property
    def public(self) -> IssuerPublicKey:
        return self.key.public

    def issue_credential(self, subject_id: str, pk_s: SubjectPublicKey, s_att: Iterable[str]) -> Credential:
        attrs = tuple(sorted(set(s_att)))
        if not attrs:
            raise ValueError("attribute set must not be empty")
        h = H_set(attrs)
        r = random_scalar()
        c1 = bls.add(bls.add(self.key.sk_aa2, bls.multiply(pk_s.pk_s1, _inv(h))), bls.multiply(self.pp.mpk1, r))
        c2 = bls.multiply(bls.G1, (-r) % P)
        c3 = bls.multiply(bls.G2, r)
        c_u = {a: bls.multiply(H1(a), r) for a in attrs}
        self.registry[subject_id] = IssuanceRecord(pk_s.pk_s1, h)
        return Credential(c1, c2, c3, c_u)


# --------------------------------------------------------------------------
# Subject: obtainCredential() and showCredential() (Sections 5.2, 5.3)
# --------------------------------------------------------------------------

class Subject:
    def __init__(self, subject_id: str, pp: PublicParameters, key: SubjectKey) -> None:
        self.subject_id = subject_id
        self.pp = pp
        self.key = key
        self.credential: Credential | None = None
        self.attributes: tuple[str, ...] = ()

    def obtain_credential(self, cc: Credential, s_att: Iterable[str], aa_public: IssuerPublicKey) -> bool:
        """obtainCredential(): verify Eq. (1) and store CC and sAtt if valid."""
        attrs = tuple(sorted(set(s_att)))
        ok = verify_equation_1(self.pp, aa_public, self.key.public, cc, attrs)
        if ok:
            self.credential, self.attributes = cc, attrs
        return ok

    def show_credential(self, structure: AccessStructure, message: Scalar) -> PresentationCertificate:
        """showCredential(sk_s, CC, sAtt, m, tau) -> PC."""
        if self.credential is None:
            raise RuntimeError("no credential obtained")
        nu = reconstruction_vector(structure, self.attributes)
        if nu is None:
            raise PolicyNotSatisfied(structure.policy)
        return build_presentation(self.pp, self.key, self.credential, self.attributes, structure, nu, message)


def build_presentation(
    pp: PublicParameters,
    key: SubjectKey,
    cc: Credential,
    s_att: tuple[str, ...],
    structure: AccessStructure,
    nu: tuple[int, ...],
    message: Scalar,
) -> PresentationCertificate:
    cc_attrs = set(cc.c_u)
    m_att = {structure.row_labels[i] for i, c in enumerate(nu) if c % P}
    if not m_att <= cc_attrs:
        raise PolicyNotSatisfied("attribute key missing for a used row")
    n_att = set(s_att) - m_att

    r_prime = random_scalar()
    r_trace = random_scalar()                                       # independent r'' for the tracing pair
    c1hat = bls.add(cc.c1, bls.multiply(pp.mpk1, r_prime))          # C1^ = C1 mpk1^{r'} (only inside S1)
    c1p = bls.add(cc.c1, bls.multiply(pp.mpk1, r_trace))            # C1' = C1 mpk1^{r''}
    c2p = bls.add(cc.c2, bls.multiply(bls.G1, (-r_trace) % P))      # C2' = g1^{-(r+r'')}
    c3p = bls.add(cc.c3, bls.multiply(bls.G2, r_prime))             # C3' = g2^{r+r'}

    beta = bls.Z1
    omega = []
    for i, coeff in enumerate(nu):
        coeff %= P
        if coeff == 0:
            omega.append(bls.Z2)
            continue
        label = structure.row_labels[i]
        u_prime = bls.add(cc.c_u[label], bls.multiply(H1(label), r_prime))  # U^{r+r'}
        beta = bls.add(beta, bls.multiply(u_prime, coeff))                   # beta = prod (C'_u)^{nu_i}
        omega.append(bls.multiply(c3p, coeff))                               # w_i = (C3')^{nu_i}

    r_s = random_scalar()
    delta = random_scalar()                                                 # fresh per session
    m = message % P
    s1 = bls.add(bls.add(c1hat, beta), bls.multiply(bls.G1, (r_s * m + delta) % P))  # S1 = C1^ beta g1^{r_s m + delta}
    s2 = bls.multiply(bls.G1, r_s)                                          # S2 = g1^{r_s}
    h_m, h_n = H_set(m_att), H_set(n_att)
    a_m = bls.multiply(s2, _inv(h_m))                                       # A_m = S2^{1/H(mAtt)}
    a_n = bls.multiply(bls.G2, ((key.sk_s * _inv(h_n) + delta * h_m) * _inv(r_s)) % P)  # A_n = g2^{(sk_s/H(nAtt) + delta H(mAtt))/r_s}
    return PresentationCertificate(tuple(omega), s1, s2, c1p, c2p, a_m, a_n)


# --------------------------------------------------------------------------
# Verification equations
# --------------------------------------------------------------------------

def verify_equation_1(
    pp: PublicParameters, aa: IssuerPublicKey, pk: SubjectPublicKey, cc: Credential, s_att: Iterable[str]
) -> bool:
    h_inv = _inv(H_set(s_att))
    lhs = pair(cc.c1, bls.G2)
    rhs = aa.pk_aa1 * pair(bls.multiply(pk.pk_s1, h_inv), bls.G2) * pair(pp.mpk1, cc.c3)
    return lhs == rhs


def verify_credential(
    pp: PublicParameters,
    aa: IssuerPublicKey,
    pc: PresentationCertificate,
    structure: AccessStructure,
    message: Scalar,
) -> bool:
    """verifyCredential(pk_aa, PC, A_m, A_n, m, tau) -> {0,1}: Eq. (2), run by the PDP."""
    if len(pc.omega) != structure.rows:
        return False
    # PDP's fresh random vector (1, r_2, ..., r_k) and rho_i = sum_j r_j M_ij.
    r = [1] + [random_scalar() for _ in range(structure.columns - 1)]
    rho = [sum(r[j] * structure.matrix[i][j] for j in range(structure.columns)) % P for i in range(structure.rows)]
    lhs = pair(pc.s1, bls.G2)
    rhs = aa.pk_aa1 * pair(pc.a_m, pc.a_n) * pair(pc.s2, bls.multiply(bls.G2, message % P))
    for i, w in enumerate(pc.omega):
        if _is_inf(w):
            continue  # e(X, 1_G2) = 1
        base = bls.add(H1(structure.row_labels[i]), bls.multiply(pp.mpk1, rho[i]))
        rhs = rhs * pair(base, w)
    return lhs == rhs


# --------------------------------------------------------------------------
# AU: Access Credential Inspection Phase (Section 5.4)
# --------------------------------------------------------------------------

@dataclass
class AttributeAuditor:
    key: AuditorKey
    aa_public: IssuerPublicKey
    revocation_list: set[tuple[int, int]] = field(default_factory=set)

    def trace_credential(self, pc: PresentationCertificate) -> Point:
        """traceCredential(): beta* = C1' (C2')^alpha (ElGamal decryption)."""
        return bls.add(pc.c1_prime, bls.multiply(pc.c2_prime, self.key.alpha))

    def judge_credential(self, beta_star: Point, record: IssuanceRecord) -> bool:
        """judgeCredential(): Eq. (3) e(beta*,g2) pk_aa1^{-1} = e(pk_s1^{1/H(sAtt)}, g2)."""
        lhs = pair(beta_star, bls.G2) / self.aa_public.pk_aa1
        rhs = pair(bls.multiply(record.pk_s1, _inv(record.h_satt)), bls.G2)
        return lhs == rhs

    def identify(self, pc: PresentationCertificate, aa: AttributeAuthority) -> str | None:
        """traceCredential() <-> judgeCredential() in collaboration with the AA registry."""
        beta_star = self.trace_credential(pc)
        for subject_id, record in aa.registry.items():
            if self.judge_credential(beta_star, record):
                return subject_id
        return None

    # Revocation list RL (Definition 4.6), keyed by the subject's pk_s1.
    def revoke(self, pk: SubjectPublicKey) -> None:
        self.revocation_list.add(point_id(pk.pk_s1))

    def is_revoked(self, pk_s1: Point) -> bool:
        return point_id(pk_s1) in self.revocation_list


def point_id(point: Point) -> tuple[int, int]:
    x, y = bls.normalize(point)
    return int(x.n), int(y.n)
