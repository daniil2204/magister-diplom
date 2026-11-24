"""Risk, priority and budget distribution (formulas 2.14-2.18).

All components lie in [0; 1], so 0 <= P(t) <= R(t) <= S(v) <= 1. Because M >= 0.5 we also have
R(t) >= 0.1 * S(v): no target is ever assigned zero risk, which is deliberate -- a target with
zero risk would be indistinguishable from a target that was never generated.
"""

from __future__ import annotations

from hsa.config import Config
from hsa.model import Target


def controllability(target: Target) -> float:
    """A(t) = |{e in E_t : Ctrl(e)}| / |E_t| (2.14).

    An empty E_t yields 1: with no information the risk is estimated pessimistically so that the
    target does not sink to the tail of the queue.
    """
    total = len(target.context.key_expressions)
    if total == 0:
        return 1.0
    return target.controllable / total


def exposure(target: Target) -> float:
    """D(t) = 1 / (1 + g(t)) (2.15)."""
    return 1.0 / (1.0 + target.guard_count)


def value_factor(target: Target) -> float:
    """M(t): 1 if the entry point moves value, otherwise 0.5."""
    return 1.0 if target.context.moves_value else 0.5


def risk(target: Target, config: Config) -> float:
    """R(t) = S(v) * (alpha*A + beta*D + gamma*M) (2.16)."""
    return config.severity_of(target.vuln_class) * (
        config.alpha * controllability(target)
        + config.beta * exposure(target)
        + config.gamma * value_factor(target)
    )


def priority(target: Target, config: Config) -> float:
    """P(t) = R(t) * (1 + b(t))^(-lambda) (2.17)."""
    return risk(target, config) * (1.0 + target.branch_count) ** (-config.lam)


def order(targets: list[Target], config: Config) -> list[Target]:
    """Queue order: descending P(t), with a deterministic tie-break.

    M4 replaces this with a seeded random permutation; that is handled by the caller, which owns
    the random generator.
    """
    return sorted(
        targets,
        key=lambda t: (-priority(t, config), str(t.point), t.entry_point.canonical_name),
    )


def budgets(targets: list[Target], config: Config) -> dict[int, float]:
    """B_t = max(B_min, B * P(t) / sum P) (2.18), keyed by id of the target.

    The sum of the allocations may exceed B when many targets hit the floor. That is intended:
    the queue stops when the contract budget is spent, and whatever is left over from a target
    that finished early rolls forward to the next one.
    """
    priorities = {id(t): priority(t, config) for t in targets}
    total = sum(priorities.values())
    if total <= 0.0:
        return {id(t): config.b_min for t in targets}
    return {
        id(t): max(config.b_min, config.budget * priorities[id(t)] / total) for t in targets
    }
