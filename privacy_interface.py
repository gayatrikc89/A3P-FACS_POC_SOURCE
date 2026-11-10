"""Privacy-aware module interface used by the PIP (Section 5.6, Figure 2).

The module is intentionally NON-cryptographic. It performs sensitivity-based
data minimisation: depending on the sensitivity index (SI) that the privacy
policy manager assigns to a resource, the PIP releases to the context handler
and PDP only the object and environment attributes that the applicable
policies need. Released attributes are visible in plaintext to these
(honest-but-curious) components; nothing here encrypts or hides them.

    SI 0 (No Privacy)      : release all object and environment attributes
    SI 1 (Partial Privacy) : release policy-relevant object attributes and
                             all environment attributes
    SI 2 (Full Privacy)    : release only policy-relevant object and
                             environment attributes
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

AttributeMap = dict[str, str]


@dataclass(frozen=True)
class ResourceRecord:
    """Entry of the object / environment attribute store (storage layer)."""

    object_id: str
    object_attributes: AttributeMap
    environment_attributes: AttributeMap


@dataclass(frozen=True)
class ReleasedAttributeView:
    """Minimised attribute view returned by fetchAttributes()."""

    object_id: str
    sensitivity_index: int
    object_attributes: AttributeMap
    environment_attributes: AttributeMap
    suppressed_object_count: int
    suppressed_environment_count: int

    @property
    def released_count(self) -> int:
        return len(self.object_attributes) + len(self.environment_attributes)

    @property
    def suppressed_count(self) -> int:
        return self.suppressed_object_count + self.suppressed_environment_count

    @property
    def total_count(self) -> int:
        return self.released_count + self.suppressed_count

    @property
    def release_ratio(self) -> float:
        return 0.0 if self.total_count == 0 else self.released_count / self.total_count


@dataclass
class PrivacyPolicyManager:
    """Holds the 'DB Privacy Policy' of Figure 2: SI label per resource."""

    sensitivity: dict[str, int] = field(default_factory=dict)

    def label(self, object_id: str, sensitivity_index: int) -> None:
        if sensitivity_index not in (0, 1, 2):
            raise ValueError("sensitivity index must be 0, 1 or 2")
        self.sensitivity[object_id] = sensitivity_index

    def sensitivity_of(self, object_id: str) -> int:
        # Unlabelled resources default to the most restrictive level.
        return self.sensitivity.get(object_id, 2)


class PrivacyAwareModuleInterface:
    """Minimises object/environment attributes before they leave the PIP."""

    def __init__(self, privacy_manager: PrivacyPolicyManager) -> None:
        self.privacy_manager = privacy_manager

    def minimise(
        self,
        record: ResourceRecord,
        policy_object_keys: frozenset[str],
        policy_environment_keys: frozenset[str],
    ) -> ReleasedAttributeView:
        si = self.privacy_manager.sensitivity_of(record.object_id)
        if si == 0:
            object_keys = set(record.object_attributes)
            environment_keys = set(record.environment_attributes)
        elif si == 1:
            object_keys = set(policy_object_keys)
            environment_keys = set(record.environment_attributes)
        else:
            object_keys = set(policy_object_keys)
            environment_keys = set(policy_environment_keys)
        obj = _project(record.object_attributes, object_keys)
        env = _project(record.environment_attributes, environment_keys)
        return ReleasedAttributeView(
            object_id=record.object_id,
            sensitivity_index=si,
            object_attributes=obj,
            environment_attributes=env,
            suppressed_object_count=len(record.object_attributes) - len(obj),
            suppressed_environment_count=len(record.environment_attributes) - len(env),
        )

    @staticmethod
    def full_view(record: ResourceRecord, si: int) -> ReleasedAttributeView:
        """Baseline without minimisation (used only for comparison)."""
        return ReleasedAttributeView(
            record.object_id, si, dict(record.object_attributes),
            dict(record.environment_attributes), 0, 0,
        )


def synthetic_resource(
    object_attribute_count: int, environment_attribute_count: int, object_id: str | None = None
) -> ResourceRecord:
    """Synthetic resource used by the tests and benchmarks."""
    if object_attribute_count < 1 or environment_attribute_count < 1:
        raise ValueError("attribute counts must be positive")
    return ResourceRecord(
        object_id=object_id or f"resource-{object_attribute_count}-{environment_attribute_count}",
        object_attributes={f"oatt_{i:04d}": f"oval_{i:04d}" for i in range(object_attribute_count)},
        environment_attributes={f"eatt_{i:04d}": f"eval_{i:04d}" for i in range(environment_attribute_count)},
    )


def _project(attributes: Mapping[str, str], keys: set[str]) -> AttributeMap:
    return {k: attributes[k] for k in sorted(keys) if k in attributes}
