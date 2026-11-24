"""Tests for the directed search of `hsa.symexec.engine` (week 3).

Unlike `test_predicates`, which places the state by hand on a straight line, these drive the whole
engine: it walks the interprocedural expansion, forks on IF / IFLOOP, inlines modifiers and internal
calls, bounds loops and only then calls the predicate. So every fixture here exercises a piece of
control flow the linear harness could not reach -- a modifier guard, a branch, a loop, an internal
call across a depth boundary.

Reentrancy (SC08) is driven here too: the one-level re-entry model needs the whole engine, because
its second stage runs a public function g from the call-moment snapshot, and the lock that refutes
`nonReentrant` lives in a modifier the engine must inline.
"""

from __future__ import annotations

import pytest

from hsa.config import Config, Mode, VulnClass
from hsa.model import UnknownReason, Verdict
from hsa.static import DETECTORS
from hsa.static.base import Analysis
from hsa.symexec.engine import analyze_target
from tests.conftest import load


def _targets(name: str) -> tuple[Analysis, list]:
    compilation = load(name)
    contract = next(c for c in compilation.slither.contracts if not c.is_library)
    analysis = Analysis.build(compilation, contract)
    targets = [t for detector in DETECTORS for t in detector.detect(analysis)]
    return analysis, targets


def _one(name: str, vuln_class: VulnClass, function_name: str):
    """The single target of a class in a function. Fails loudly if there is not exactly one."""
    analysis, targets = _targets(name)
    matching = [
        t
        for t in targets
        if t.vuln_class is vuln_class and t.function.name == function_name
    ]
    assert len(matching) == 1, [str(t) for t in matching]
    return analysis, matching[0]


def _analyze(name: str, vuln_class: VulnClass, function_name: str, config: Config = None) -> object:
    analysis, target = _one(name, vuln_class, function_name)
    return analyze_target(analysis, target, config or Config(), budget=120.0)


# ------------------------------------------------------------------- SC10 delegatecall


def test_controlled_delegatecall_is_confirmed() -> None:
    """`target.delegatecall(data)`: the destination is an argument, so the path reaches it."""
    outcome = _analyze("Delegatecall_proxy", VulnClass.DC, "forward")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_storage_delegatecall_is_refuted() -> None:
    """`implementation.delegatecall(data)`: the destination is storage, Ctrl(a) is false."""
    outcome = _analyze("Delegatecall_proxy", VulnClass.DC, "run")
    assert outcome.verdict is Verdict.REFUTED


# ------------------------------------------------------------------- SC01 access control


def test_unprotected_write_is_confirmed() -> None:
    """`owner = n` with no guard: the attacker reaches the privileged write."""
    outcome = _analyze("Access_unprotected", VulnClass.AC, "setOwner")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_modifier_guarded_write_is_refuted() -> None:
    """`kill()` is onlyOwner: the engine inlines the modifier, so require(sender == owner) is on
    the path and contradicts the attacker model sender != owner."""
    outcome = _analyze("Access_unprotected", VulnClass.AC, "kill")
    assert outcome.verdict is Verdict.REFUTED


# ------------------------------------------------------------------- SC06 unchecked call


def test_discarded_call_result_is_confirmed() -> None:
    """`to.call{value}("")` then a write: the success flag is free, so r = false is reachable."""
    outcome = _analyze("Unchecked_call", VulnClass.UC, "payout")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_unchecked_call_behind_an_if_is_confirmed() -> None:
    """Reentrancy_if guards with `if`, so the write is reached only on the true branch: the engine
    must fork on the IF to reach it. Confirmed under both M1 (pruned) and M3 (whole graph)."""
    for mode in (Mode.M1, Mode.M3):
        outcome = _analyze("Reentrancy_if", VulnClass.UC, "withdraw", Config(mode=mode))
        assert outcome.verdict is Verdict.CONFIRMED, mode
        assert outcome.counterexample is not None


# ------------------------------------------------------------------------- SC09 overflow


def test_unguarded_subtraction_is_confirmed() -> None:
    """`balances[msg.sender] -= amount` with no require: CONFIRMED by the strong condition."""
    outcome = _analyze("Overflow_sub", VulnClass.OV, "withdrawAll")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_guarded_subtraction_is_refuted() -> None:
    """`require(balances[msg.sender] >= v); balances[msg.sender] -= v` cannot underflow."""
    outcome = _analyze("Overflow_guarded", VulnClass.OV, "burn")
    assert outcome.verdict is Verdict.REFUTED


# ------------------------------------------------------- loop unrolling (k), internal calls, depth


def test_the_loop_is_refuted_at_k_one_and_confirmed_at_k_two() -> None:
    """Overflow_loop: `acc += step` overflows only once acc has a term in it, i.e. on the second
    iteration. k = 1 explores one iteration (acc = 0, no overflow) and k = 2 reaches the second."""
    analysis, target = _one("Overflow_loop", VulnClass.OV, "accumulate")
    refuted = analyze_target(analysis, target, Config(k_unroll=1), budget=120.0)
    assert refuted.verdict is Verdict.REFUTED
    confirmed = analyze_target(analysis, target, Config(k_unroll=2), budget=120.0)
    assert confirmed.verdict is Verdict.CONFIRMED
    assert confirmed.counterexample is not None


def test_internal_call_behind_a_modifier_is_refuted() -> None:
    """Mint_internal: both OV targets live in `_mint`, reached through `mint`'s onlyOwner. The
    engine inlines the internal call and the modifier, so the attacker cannot pass the guard."""
    analysis, targets = _targets("Mint_internal")
    overflow = [t for t in targets if t.vuln_class is VulnClass.OV]
    assert len(overflow) == 2
    for target in overflow:
        outcome = analyze_target(analysis, target, Config(), budget=120.0)
        assert outcome.verdict is Verdict.REFUTED, str(target)


def test_a_target_deeper_than_d_is_unknown() -> None:
    """With d = 0 the target in `_mint` is one inlining step past the entry point `mint`."""
    analysis, targets = _targets("Mint_internal")
    overflow = [t for t in targets if t.vuln_class is VulnClass.OV]
    for target in overflow:
        outcome = analyze_target(analysis, target, Config(d_inline=0), budget=120.0)
        assert outcome.verdict is Verdict.UNKNOWN
        assert outcome.reason is UnknownReason.DEPTH_EXCEEDED


# ----------------------------------------------------- internal-call frames, returns, recursion


def test_internal_call_return_reaches_the_caller() -> None:
    """Safemath_internal: `s = addUnchecked(a, b)` then `s + 1`. The overflow is reachable only if
    the callee's return value is carried into `s`; without propagation s is 0 and s + 1 never
    overflows. CONFIRMED proves the return crosses the call boundary (the SafeMath-sum case)."""
    outcome = _analyze("Safemath_internal", VulnClass.OV, "store")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_callee_arguments_do_not_clobber_the_caller() -> None:
    """Name_collision: caller and callee both use locals a, b. The guarded `a - b` in `outer` is
    REFUTED only if the frame keeps `outer`'s a, b apart from `inner(b, a)`'s; a flat map would swap
    them and the subtraction would wrongly underflow."""
    outcome = _analyze("Name_collision", VulnClass.OV, "outer")
    assert outcome.verdict is Verdict.REFUTED


def test_recursive_call_is_unknown_recursion() -> None:
    """Recursive_sum: `rec` calls itself, which the ICFG does not unroll. The path through the
    self-call cannot be modelled and must surface as UNKNOWN `recursion`, outweighing the REFUTED
    base-case path -- not a silent REFUTED."""
    outcome = _analyze("Recursive_sum", VulnClass.OV, "run")
    assert outcome.verdict is Verdict.UNKNOWN
    assert outcome.reason is UnknownReason.RECURSION


# --------------------------------------------------- internal vs public library calls


def test_internal_library_call_return_reaches_the_caller() -> None:
    """Safemath_library: `s = a.add(b)` is an internal library function, which solc inlines, so the
    engine models it exactly -- the callee's return `a + b` is carried into s and `s + 1` overflows.
    The library analogue of test_internal_call_return_reaches_the_caller."""
    outcome = _analyze("Safemath_library", VulnClass.OV, "store")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_chained_library_calls_in_one_node_are_confirmed() -> None:
    """Safemath_library.chain: `a.add(b).sub(c)` is two internal library calls in a single node. The
    engine must inline both and carry both returns back, so s = (a + b) - c and `s + 1` overflows.
    This exercises the lifted one-inlined-call-per-node limit on the required SafeMath chain."""
    outcome = _analyze("Safemath_library", VulnClass.OV, "chain")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None


def test_public_library_call_result_is_opaque() -> None:
    """Library_public: `a.addPub(b)` is a public library function, i.e. a DELEGATECALL to unknown
    code. Its result is a fresh symbol with no path constraint, so the static stage produces no OV
    target and the overflow is not confirmable -- the opposite of the internal-library case."""
    _, targets = _targets("Library_public")
    assert [t for t in targets if t.vuln_class is VulnClass.OV] == []


# ------------------------------------------------------------------- SC08 reentrancy (phi_RE)


def test_reentrancy_self_is_confirmed() -> None:
    """Vault.withdraw: the balance is read, ether is sent, the balance is zeroed only afterwards.
    The attacker re-enters `withdraw` itself (it has no guard) while `balances` still holds the old
    value, so the write is CONFIRMED and the re-entry function is `withdraw`."""
    outcome = _analyze("Vault", VulnClass.RE, "withdraw")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None
    assert outcome.counterexample.reentry_function == "Vault.withdraw()"


def test_reentrancy_through_an_argument_amount_is_confirmed() -> None:
    """Reentrancy_if guards with an `if`, not a `require`, and the amount is an argument. The write
    `credit[msg.sender] -= amount` after the call is still CONFIRMED under both M1 and M3."""
    for mode in (Mode.M1, Mode.M3):
        outcome = _analyze("Reentrancy_if", VulnClass.RE, "withdraw", Config(mode=mode))
        assert outcome.verdict is Verdict.CONFIRMED, mode
        assert outcome.counterexample is not None


def test_reentrancy_guard_refutes() -> None:
    """Vault_fixed_guard.withdraw is `nonReentrant`: `locked == true` in the snapshot makes a second
    entry into any public function reading or writing `balances` unsat. The only candidate g is
    `withdraw` itself (deposit has no explicit condition on v), and its lock refutes it."""
    outcome = _analyze("Vault_fixed_guard", VulnClass.RE, "withdraw")
    assert outcome.verdict is Verdict.REFUTED


def test_cross_function_reentrancy_defeats_a_single_function_lock() -> None:
    """Reentrancy_cross: `withdraw` is `nonReentrant` but `transfer` is not. The attacker re-enters
    the unguarded `transfer`, which moves the still-stale balance, so the write in `withdraw` is
    CONFIRMED -- the classic DAO shape -- and the re-entry function is `transfer`, not `withdraw`."""
    outcome = _analyze("Reentrancy_cross", VulnClass.RE, "withdraw")
    assert outcome.verdict is Verdict.CONFIRMED
    assert outcome.counterexample is not None
    assert outcome.counterexample.reentry_function == "ReentrancyCross.transfer(address,uint256)"


def test_send_does_not_produce_a_reentrancy_target() -> None:
    """Unchecked_call.payoutSend uses `send` (2300 gas), which cannot re-enter, so the static stage
    produces no RE target for it at all -- only the UC target survives."""
    _, targets = _targets("Unchecked_call")
    re = [t for t in targets if t.vuln_class is VulnClass.RE and t.function.name == "payoutSend"]
    assert re == []
