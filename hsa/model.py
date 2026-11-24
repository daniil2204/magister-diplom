"""Data model shared by the static stage, the symbolic engine and the report.

Formula numbers refer to chapter 2 of the thesis.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from hsa.config import VulnClass

if TYPE_CHECKING:  # pragma: no cover - typing only
    from slither.core.cfg.node import Node
    from slither.core.declarations import Function


class EventKind(enum.Enum):
    """Kinds of events recorded in the trace tau of the symbolic state (2.4)."""

    READ = "read"
    WRITE = "write"
    CALL = "call"  # external call with value transfer semantics
    LCALL = "lcall"  # low-level call whose success flag is a value
    DCALL = "dcall"  # delegatecall
    PRIV = "priv"  # privileged operation
    UNCHECKED_OP = "op"  # arithmetic operation in an unchecked context


class Verdict(enum.Enum):
    """Verdict of one target. Aggregation order: CONFIRMED > UNKNOWN > REFUTED."""

    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"
    REFUTED = "REFUTED"


#: Strength used when aggregating targets into an evaluation unit (class, function).
VERDICT_STRENGTH: dict[Verdict, int] = {
    Verdict.REFUTED: 0,
    Verdict.UNKNOWN: 1,
    Verdict.CONFIRMED: 2,
}


class UnknownReason(enum.Enum):
    """Why a target ended as UNKNOWN.

    Every UNKNOWN carries one, with no exception: `reason: null` would make "the symbolic stage
    was never run" indistinguishable from a bug that dropped the reason.
    """

    STATIC_ONLY = "static_only"  # M2: no symbolic execution, the target stays a static warning
    TIMEOUT = "timeout"  # B_t exhausted
    BUDGET_EXHAUSTED = "budget_exhausted"  # the queue never reached the target
    SKIPPED_CONFIRMED = "skipped_confirmed"  # same (class, node) already CONFIRMED elsewhere
    DEPTH_EXCEEDED = "depth_exceeded"  # target nested deeper than d from the entry point
    RECURSION = "recursion"  # a path reached a call to a function already on the stack
    UNSUPPORTED_OP = "unsupported_op"  # e.g. assembly
    SOLVER_UNKNOWN = "solver_unknown"
    STORAGE_DEPENDENT = "storage_dependent"  # OV: weak sat, strong proven unsat
    ANALYSIS_ERROR = "analysis_error"  # caught exception


@dataclass(frozen=True)
class ProgramPoint:
    """A point in the program: (function, node, operation index)."""

    function: "Function"
    node: "Node"
    op_index: int

    @property
    def lines(self) -> list[int]:
        return list(self.node.source_mapping.lines)

    def __str__(self) -> str:
        line = self.lines[0] if self.lines else -1
        return f"{self.function.canonical_name}@{line}#{self.op_index}"


@dataclass
class Context:
    """ctx(t) = <v, f, E_t, G_t, M_t> (2.13).

    The whole context is computed from the entry point: an onlyOwner on the public caller
    protects an otherwise unguarded internal callee.
    """

    vuln_class: VulnClass
    entry_point: "Function"
    key_expressions: list[Any] = field(default_factory=list)  # E_t
    guards: list["Node"] = field(default_factory=list)  # G_t, dominating guard conditions
    moves_value: bool = False  # M_t: ether transfer or mapping(address => uint) write
    #: For RE and UC the target is the state write AFTER the call; this is the call node itself.
    call_node: Optional["Node"] = None


@dataclass
class Target:
    """A target t produced by the static stage.

    t = (entry point f_pub, node in function h) plus the class and the context. A node reachable
    from several public callers yields one target per entry point.
    """

    point: ProgramPoint
    context: Context
    controllable: int = 0  # |{e in E_t : Ctrl(e)}|
    guard_count: int = 0  # g(t)
    branch_count: int = 0  # b(t), conditional nodes in N*_t
    call_depth: int = 0  # distance from the entry point along the call chain

    @property
    def vuln_class(self) -> VulnClass:
        return self.context.vuln_class

    @property
    def entry_point(self) -> "Function":
        return self.context.entry_point

    @property
    def function(self) -> "Function":
        """The function CONTAINING the target node -- the evaluation unit, not the entry point."""
        return self.point.function

    @property
    def unit(self) -> tuple[str, str]:
        """Evaluation unit: (SWC class, function containing the target node).

        Keyed by the SWC code, not by VulnClass: the datasets are labelled with five classes, and
        AC and TO are two predicates over the same one. A tx.origin check guarding a privileged
        write produces both an AC and a TO target, but a single SC01 unit.
        """
        return (self.vuln_class.swc, self.function.canonical_name)

    @property
    def node_key(self) -> tuple[VulnClass, str, int]:
        """Identity used for skipping nodes already CONFIRMED from another entry point."""
        return (self.vuln_class, self.point.function.canonical_name, self.point.node.node_id)

    def __str__(self) -> str:
        return f"{self.vuln_class.name} {self.point} via {self.entry_point.name}"


@dataclass
class Event:
    """One entry of the trace tau.

    A CALL / LCALL / DCALL event carries the snapshot of the symbolic state at the moment of the
    call. The snapshot lives here rather than in Context so that Context and SymState stay
    separate structures.

    `result` is r_i of (2.7): the success flag a low-level call returns as a value. It sits beside
    the snapshot for the same reason -- phi_UC reads the trace, so what the predicate needs must
    be in the trace and not only in rho.

    `can_reenter` says whether the callee gets enough gas to call back. It is false for `transfer`,
    `send` (2300 gas) and `staticcall`, which is the criterion the static stage already uses for
    SC08. Without the flag phi_RE could latch onto a `transfer` in the trace even though no RE
    target was ever generated for it.
    """

    kind: EventKind
    point: ProgramPoint
    variable: Optional[Any] = None  # state variable for READ / WRITE / PRIV
    destination: Optional[Any] = None  # callee address expression for the call kinds
    value: Optional[Any] = None  # ether transferred by the call, None if no value is attached
    result: Optional[Any] = None  # r_i of (2.7): success flag, set for LCALL and DCALL
    can_reenter: bool = False  # set for the call kinds only
    snapshot: Optional["SymState"] = None  # Sigma_i, set for the call kinds only


@dataclass
class SymState:
    """Symbolic state Sigma = <rho, mu, PC, tau> (2.4)."""

    rho: dict[str, Any] = field(default_factory=dict)  # variables -> Z3 terms
    mu: dict[str, Any] = field(default_factory=dict)  # storage: mappings and arrays as Z3 Arrays
    pc: list[Any] = field(default_factory=list)  # path condition, conjunction of Z3 constraints
    tau: list[Event] = field(default_factory=list)  # event trace
    #: X_env and the other transaction properties (msg.*, tx.*, block.*): one term each, fixed for
    #: the whole transaction. Kept out of rho so that saving and restoring a call frame -- which
    #: snapshots rho -- never touches them; otherwise `block.timestamp` read inside a callee would
    #: become a fresh, unrelated symbol once the frame was restored.
    env: dict[str, Any] = field(default_factory=dict)

    def fork(self) -> "SymState":
        """Shallow copy for a branch. Z3 terms are immutable, so copying containers suffices."""
        return SymState(
            dict(self.rho), dict(self.mu), list(self.pc), list(self.tau), dict(self.env)
        )


@dataclass
class Counterexample:
    """Witness extracted from a satisfying model."""

    function: str  # the entry point actually invoked
    arguments: dict[str, Any] = field(default_factory=dict)
    sender: Optional[Any] = None
    value: Optional[Any] = None
    storage: dict[str, Any] = field(default_factory=dict)  # relevant state variables
    reentry_function: Optional[str] = None  # RE only: the function re-entered

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "function": self.function,
            "arguments": {k: str(v) for k, v in self.arguments.items()},
            "storage": {k: str(v) for k, v in self.storage.items()},
        }
        if self.sender is not None:
            data["sender"] = str(self.sender)
        if self.value is not None:
            data["value"] = str(self.value)
        if self.reentry_function is not None:
            data["reentry_function"] = self.reentry_function
        return data


@dataclass
class TargetResult:
    """Everything the report needs about one target."""

    target: Target
    verdict: Verdict
    risk: float  # R(t)
    priority: float  # P(t)
    budget: float  # B_t allocated
    elapsed: float  # seconds spent on this target
    time_to_verdict: float  # seconds from the start of the contract analysis
    reason: Optional[UnknownReason] = None
    counterexample: Optional[Counterexample] = None

    def to_json(self) -> dict[str, Any]:
        lines = self.target.point.lines
        return {
            "class": self.target.vuln_class.name,
            "swc": self.target.vuln_class.swc,
            "entry_point": self.target.entry_point.canonical_name,
            "function": self.target.function.canonical_name,
            "node_id": self.target.point.node.node_id,
            "op_index": self.target.point.op_index,
            "line": lines[0] if lines else None,
            "R": round(self.risk, 6),
            "P": round(self.priority, 6),
            "b": self.target.branch_count,
            "budget": round(self.budget, 3),
            "verdict": self.verdict.value,
            "elapsed": round(self.elapsed, 3),
            "time_to_verdict": round(self.time_to_verdict, 3),
            "reason": self.reason.value if self.reason else None,
            "counterexample": self.counterexample.to_json() if self.counterexample else None,
        }


def aggregate(results: list[TargetResult]) -> dict[tuple[str, str], Verdict]:
    """Aggregate targets into evaluation units (SWC class, function containing the node).

    The strongest verdict wins: CONFIRMED > UNKNOWN > REFUTED.
    """
    units: dict[tuple[str, str], Verdict] = {}
    for result in results:
        key = result.target.unit
        current = units.get(key)
        if current is None or VERDICT_STRENGTH[result.verdict] > VERDICT_STRENGTH[current]:
            units[key] = result.verdict
    return units
