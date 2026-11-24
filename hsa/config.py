"""Configuration of the method.

Every coefficient of chapter 2 lives here and nowhere else: the sensitivity analysis varies them,
so they must never be hard-coded at the point of use.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace


class VulnClass(enum.Enum):
    """Vulnerability classes covered by the method (table 2.3).

    Six classes, five SWC codes: AC and TO are two different predicates (2.8) and (2.9) over the
    same SWC-106/115 family, so they must stay separate members. Giving both the literal value
    "SC01" would make TO an ALIAS of AC in a Python enum and silently delete the class.
    """

    RE = "RE"  # reentrancy
    UC = "UC"  # unchecked low-level call
    AC = "AC"  # access control
    TO = "TO"  # tx.origin authentication
    DC = "DC"  # controlled delegatecall
    OV = "OV"  # integer overflow / underflow

    @property
    def swc(self) -> str:
        """The SWC class used by the dataset labels and the evaluation unit."""
        return _SWC[self]


#: The five classes the datasets are mapped onto ("Відображення базових інструментів").
_SWC: dict[VulnClass, str] = {
    VulnClass.RE: "SC08",
    VulnClass.UC: "SC06",
    VulnClass.AC: "SC01",
    VulnClass.TO: "SC01",
    VulnClass.DC: "SC10",
    VulnClass.OV: "SC09",
}


class Mode(enum.Enum):
    """Experiment configurations M1-M4."""

    M1 = "M1"  # the full method
    M2 = "M2"  # static stage only, every target is a warning
    M3 = "M3"  # no N*_t branch pruning, DFS in SlithIR branch order
    M4 = "M4"  # random queue order with a fixed seed


#: S(v), criticality of a class. Section "Ризик і пріоритет".
DEFAULT_SEVERITY: dict[VulnClass, float] = {
    VulnClass.RE: 1.0,
    VulnClass.AC: 1.0,
    VulnClass.TO: 1.0,
    VulnClass.DC: 1.0,
    VulnClass.OV: 0.8,
    VulnClass.UC: 0.6,
}


@dataclass(frozen=True)
class Config:
    """All parameters of a single run."""

    mode: Mode = Mode.M1

    # Risk R(t) = S(v) * (alpha*A + beta*D + gamma*M), formula (2.16).
    alpha: float = 0.4
    beta: float = 0.4
    gamma: float = 0.2
    severity: dict[VulnClass, float] = field(default_factory=lambda: dict(DEFAULT_SEVERITY))

    # Priority P(t) = R(t) * (1 + b(t))^(-lam), formula (2.17).
    lam: float = 0.5

    # Symbolic execution.
    k_unroll: int = 2  # loop unrollings
    d_inline: int = 2  # inlining depth for internal calls

    # Budget B_t = max(b_min, budget * P(t) / sum P), formula (2.18).
    budget: float = 300.0  # seconds per contract
    b_min: float = 1.0  # seconds, floor per target

    # Overflow strong condition: sub-timeout = clamp(ov_strong_fraction * B_t, min, max),
    # additionally capped by the remaining budget of the target.
    ov_strong_fraction: float = 0.3
    ov_strong_min: float = 5.0
    ov_strong_max: float = 10.0

    # Reference run for the offline replay: identical large cap per target, excluded from the
    # timing measurements of M1.
    reference_cap: float = 120.0

    seed: int = 0  # M4 queue shuffling and any other randomness

    def severity_of(self, v: VulnClass) -> float:
        return self.severity[v]

    @property
    def prune_outside_nstar(self) -> bool:
        """M3 disables branch pruning; b(t) still uses N*_t in every configuration."""
        return self.mode is not Mode.M3

    @property
    def distance_guided(self) -> bool:
        """M3 replaces the distance-ordered worklist with DFS in SlithIR branch order."""
        return self.mode is not Mode.M3

    @property
    def priority_ordered(self) -> bool:
        """M4 replaces the P(t)-ordered queue with a seeded random order."""
        return self.mode is not Mode.M4

    @property
    def symbolic_execution(self) -> bool:
        """M2 stops after the static stage; every target becomes a warning."""
        return self.mode is not Mode.M2

    def with_(self, **changes: object) -> "Config":
        return replace(self, **changes)  # type: ignore[arg-type]
