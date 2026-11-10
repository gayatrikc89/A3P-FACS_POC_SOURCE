"""Linear secret sharing scheme (LSSS) access structures for A3P-FACS.

A policy predicate tau is written as a monotone Boolean formula over
attribute names using AND / OR, for example::

    "role:doctor AND (dept:icu OR dept:er)"

It is converted to an LSSS matrix (M, p) with the Lewko-Waters algorithm:
every row i of M is labelled with an attribute p(i), and an attribute set S
satisfies tau iff there is a vector nu, supported on the rows labelled by S,
with nu * M = (1, 0, ..., 0) (Section 5.3, monotone span program).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence

from py_ecc import optimized_bls12_381 as bls

P = bls.curve_order


@dataclass(frozen=True)
class AccessStructure:
    """LSSS access structure (M, p) of a policy predicate tau."""

    policy: str
    matrix: tuple[tuple[int, ...], ...]  # l x k matrix M over Z_p
    row_labels: tuple[str, ...]          # p(i): attribute labelling row i

    @property
    def rows(self) -> int:
        return len(self.matrix)

    @property
    def columns(self) -> int:
        return len(self.matrix[0])


# --------------------------------------------------------------------------
# Policy parsing (AND binds tighter than OR; parentheses allowed)
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|AND\b|OR\b|[^\s()]+)")


def _tokenize(policy: str) -> list[str]:
    tokens = _TOKEN.findall(policy)
    if "".join(t.strip() for t in tokens) != re.sub(r"\s+", "", policy):
        raise ValueError(f"cannot parse policy: {policy!r}")
    return [t.strip() for t in tokens]


def _parse(tokens: list[str]):
    pos = 0

    def expr():
        nonlocal pos
        node = term()
        while pos < len(tokens) and tokens[pos] == "OR":
            pos += 1
            node = ("OR", node, term())
        return node

    def term():
        nonlocal pos
        node = factor()
        while pos < len(tokens) and tokens[pos] == "AND":
            pos += 1
            node = ("AND", node, factor())
        return node

    def factor():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("unexpected end of policy")
        tok = tokens[pos]
        if tok == "(":
            pos += 1
            node = expr()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError("missing ')' in policy")
            pos += 1
            return node
        if tok in ("AND", "OR", ")"):
            raise ValueError(f"unexpected token {tok!r} in policy")
        pos += 1
        return ("ATTR", tok)

    tree = expr()
    if pos != len(tokens):
        raise ValueError(f"unexpected token {tokens[pos]!r} in policy")
    return tree


def build_access_structure(policy: str) -> AccessStructure:
    """Convert a Boolean policy into an LSSS matrix (Lewko-Waters)."""
    tree = _parse(_tokenize(policy))
    rows: list[tuple[list[int], str]] = []
    counter = 1

    def walk(node, vector: list[int]) -> None:
        nonlocal counter
        kind = node[0]
        if kind == "ATTR":
            rows.append((vector, node[1]))
        elif kind == "OR":
            walk(node[1], vector)
            walk(node[2], vector)
        else:  # AND
            padded = vector + [0] * (counter - len(vector))
            left = padded + [1]
            right = [0] * counter + [P - 1]
            counter += 1
            walk(node[1], left)
            walk(node[2], right)

    walk(tree, [1])
    width = counter
    matrix = tuple(
        tuple((v + [0] * (width - len(v)))[:width]) for v, _ in rows
    )
    return AccessStructure(policy, matrix, tuple(label for _, label in rows))


# --------------------------------------------------------------------------
# Reconstruction vector nu with nu * M = (1, 0, ..., 0)
# --------------------------------------------------------------------------

def reconstruction_vector(
    structure: AccessStructure, attributes: Iterable[str]
) -> tuple[int, ...] | None:
    """Return nu (one coefficient per row) or None if tau(S) = 0.

    Coefficients are non-zero only on rows whose label is in S.
    """
    owned = set(attributes)
    usable = [i for i, label in enumerate(structure.row_labels) if label in owned]
    if not usable:
        return None
    k = structure.columns
    # Solve sum_{i in usable} nu_i * M[i] = e_1, i.e. M_u^T nu = e_1 (k x |u|).
    a = [[structure.matrix[i][j] % P for i in usable] for j in range(k)]
    b = [1] + [0] * (k - 1)
    solution = _solve_mod_p(a, b)
    if solution is None:
        return None
    nu = [0] * structure.rows
    for idx, row in enumerate(usable):
        nu[row] = solution[idx] % P
    return tuple(nu)


def _solve_mod_p(a: list[list[int]], b: list[int]) -> list[int] | None:
    rows, cols = len(a), len(a[0])
    aug = [row[:] + [b[r]] for r, row in enumerate(a)]
    pivots: list[int] = []
    r = 0
    for c in range(cols):
        piv = next((i for i in range(r, rows) if aug[i][c] % P), None)
        if piv is None:
            continue
        aug[r], aug[piv] = aug[piv], aug[r]
        inv = pow(aug[r][c], -1, P)
        aug[r] = [(x * inv) % P for x in aug[r]]
        for i in range(rows):
            if i != r and aug[i][c]:
                f = aug[i][c]
                aug[i] = [(x - f * y) % P for x, y in zip(aug[i], aug[r])]
        pivots.append(c)
        r += 1
        if r == rows:
            break
    for i in range(r, rows):
        if aug[i][cols] % P:
            return None  # inconsistent: policy not satisfied
    x = [0] * cols
    for i, c in enumerate(pivots):
        x[c] = aug[i][cols]
    return x


def is_reconstruction_valid(structure: AccessStructure, nu: Sequence[int]) -> bool:
    k = structure.columns
    total = [
        sum(nu[i] * structure.matrix[i][j] for i in range(structure.rows)) % P
        for j in range(k)
    ]
    return total == [1] + [0] * (k - 1)
