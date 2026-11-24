"""Tests for the static stage.

`CONTROL` is the control table of the method: every row was derived by hand from chapter 2 and
written into the comment of the corresponding fixture BEFORE the code existed. A failure here
means either the code or the thesis text is wrong -- never the table. Change a row only together
with the fixture comment and the thesis.
"""

from __future__ import annotations

import pytest

from hsa.config import Config, VulnClass
from hsa.model import Verdict, aggregate
from hsa.priority import controllability, exposure, priority, risk, value_factor
from hsa.static import detect
from hsa.static.base import Analysis, lock_variables
from hsa.static.delegatecall import DelegatecallDetector
from hsa.static.reentrancy import ReentrancyDetector
from hsa.static.unchecked_call import UncheckedCallDetector
from tests.conftest import PINNED, load

#: (class, entry point, function containing the node, node id, op index, A, D, M, g, b, R, P)
Row = tuple[str, str, str, int, int, float, float, float, int, int, float, float]

CONTROL: dict[str, list[Row]] = {
    # The reference target of the thesis: R = 0.8, b = 2, P ~= 0.462.
    "Vault": [("RE", "withdraw", "withdraw", 6, 1, 0.5, 1.0, 1.0, 0, 2, 0.8, 0.4619)],
    # Checks-effects-interactions: nothing is written after the call.
    "Vault_fixed_cei": [],
    # The modifier tail `locked = false` also runs after the call and matches the static rule,
    # but a lock variable never produces an RE target: it is the protection, not the flaw.
    "Vault_fixed_guard": [
        ("RE", "withdraw", "withdraw", 6, 1, 0.5, 0.5, 1.0, 1, 3, 0.6, 0.3),
    ],
    "Owned_ctor": [("AC", "setOwner", "setOwner", 1, 0, 1.0, 0.5, 0.5, 1, 1, 0.7, 0.4950)],
    # addmod and mulmod cannot overflow by definition, and they are not Binary operations.
    "Modular": [],
    # Both targets live in the internal _mint but are scored from the entry point mint.
    "Mint_internal": [
        ("OV", "mint", "_mint", 1, 0, 0.5, 0.5, 1.0, 1, 1, 0.48, 0.3394),
        ("OV", "mint", "_mint", 2, 1, 0.5, 0.5, 1.0, 1, 1, 0.48, 0.3394),
    ],
    # `send` is a low-level call too: its target differs from payout's only in A (both of its
    # key expressions are arguments), which is what makes R reach 0.6 -- the UC maximum.
    "Unchecked_call": [
        ("UC", "payout", "payout", 2, 1, 0.5, 1.0, 1.0, 0, 0, 0.48, 0.48),
        ("UC", "payoutSend", "payoutSend", 2, 1, 1.0, 1.0, 1.0, 0, 0, 0.6, 0.6),
    ],
    "Access_unprotected": [
        ("AC", "kill", "kill", 1, 1, 0.5, 0.5, 1.0, 1, 1, 0.6, 0.4243),
        ("AC", "setOwner", "setOwner", 1, 0, 1.0, 1.0, 0.5, 0, 0, 0.9, 0.9),
    ],
    "Tx_origin": [
        ("AC", "setOwnerOrigin", "setOwnerOrigin", 2, 0, 1.0, 1.0, 0.5, 0, 1, 0.9, 0.6364),
        ("AC", "setOwnerSender", "setOwnerSender", 1, 0, 1.0, 0.5, 0.5, 1, 1, 0.7, 0.4950),
        ("TO", "setOwnerOrigin", "setOwnerOrigin", 2, 0, 1.0, 1.0, 0.5, 0, 1, 0.9, 0.6364),
    ],
    "Delegatecall_proxy": [
        ("AC", "upgrade", "upgrade", 1, 0, 1.0, 1.0, 0.5, 0, 0, 0.9, 0.9),
        ("DC", "forward", "forward", 1, 0, 1.0, 1.0, 0.5, 0, 0, 0.9, 0.9),
        ("DC", "run", "run", 1, 0, 0.5, 1.0, 0.5, 0, 0, 0.7, 0.7),
    ],
    # Modelled on SimpleDAO. Both targets sit on the same write, and the guard is an IF rather
    # than a require, so b = 1. The RE value comes from an argument, not from storage, which is
    # why A = 1 here and 0.5 in Vault -- the one fixture where R reaches its maximum.
    "Reentrancy_if": [
        ("RE", "withdraw", "withdraw", 4, 1, 1.0, 1.0, 1.0, 0, 1, 1.0, 0.7071),
        ("UC", "withdraw", "withdraw", 4, 1, 0.5, 1.0, 1.0, 0, 1, 0.48, 0.3394),
    ],
    # Cross-function reentry: `withdraw` is nonReentrant but `transfer` is not. The only static
    # target is the guarded `withdraw`, so every number is Vault_fixed_guard's; the cross-function
    # candidate `transfer` is a symbolic-stage concern, invisible to the static scoring.
    "Reentrancy_cross": [
        ("RE", "withdraw", "withdraw", 6, 1, 0.5, 0.5, 1.0, 1, 3, 0.6, 0.3),
    ],
    # Vault with the balance moved into a struct field. Every number is Vault's: flattening is a
    # question for the translator, and the static stage sees `accounts` written after the call
    # exactly as it sees `balances`. The op index is 2 rather than 1 because the write node now
    # carries Index, Member and Assignment.
    "Struct_bank": [("RE", "withdraw", "withdraw", 6, 2, 0.5, 1.0, 1.0, 0, 2, 0.8, 0.4619)],
    # A translator fixture: no arithmetic outside the checked default, no call, nothing
    # privileged, so the static stage has nothing to report.
    "Struct_nested": [],
    # The dataset original of Reentrancy_if, under 0.4.24, where the arithmetic is unchecked too.
    # Its UC has A = 1 while the 0.8 port has A = 0.5: `call.value(amount)()` passes no arguments,
    # whereas `call{value: amount}("")` passes the empty calldata as a literal.
    "SimpleDAO_orig": [
        ("OV", "donate", "donate", 1, 1, 0.5, 1.0, 1.0, 0, 0, 0.64, 0.64),
        ("OV", "withdraw", "withdraw", 3, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
        ("RE", "withdraw", "withdraw", 3, 1, 1.0, 1.0, 1.0, 0, 1, 1.0, 0.7071),
        ("UC", "withdraw", "withdraw", 3, 1, 1.0, 1.0, 1.0, 0, 1, 0.6, 0.4243),
    ],
    # One target on `acc += step`. The loop counter `i++` is not one: `i` depends only on the
    # literals 0 and 1, and `i < n` is a control dependency, not a data one.
    "Overflow_loop": [
        ("OV", "accumulate", "accumulate", 6, 0, 1.0, 1.0, 0.5, 0, 1, 0.72, 0.5091)
    ],
    "Overflow_mul": [
        ("OV", "batch2", "batch2", 1, 0, 0.5, 1.0, 1.0, 0, 0, 0.64, 0.64),
        ("OV", "batch2", "batch2", 3, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
        ("OV", "batch2", "batch2", 4, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
        ("OV", "batch2", "batch2", 5, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
    ],
    "Overflow_sub": [
        ("OV", "withdrawAll", "withdrawAll", 1, 1, 0.5, 1.0, 1.0, 0, 0, 0.64, 0.64)
    ],
    "Overflow_transfer": [
        ("OV", "transfer", "transfer", 2, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
        ("OV", "transfer", "transfer", 3, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
    ],
    "Overflow_guarded": [("OV", "burn", "burn", 2, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525)],
    "Overflow_args": [
        ("OV", "mulArgs", "mulArgs", 1, 1, 1.0, 1.0, 1.0, 0, 0, 0.8, 0.8),
        ("OV", "mulOwner", "mulOwner", 1, 1, 1.0, 0.5, 1.0, 1, 1, 0.64, 0.4525),
    ],
    # The only target is `s + 1`, where s is the result of addUnchecked: the sum returned from the
    # callee is a value, so s counts as controlled (A = 0.5, the literal 1 is not). The addition in
    # addUnchecked is not a target -- a bare return is not one of the sinks of the static OV rule.
    "Safemath_internal": [("OV", "store", "store", 2, 1, 0.5, 1.0, 1.0, 0, 0, 0.64, 0.64)],
    # The library form of Safemath_internal: `a.add(b)` is an internal library call, inlined as an
    # exact model, so the static stage taints its result just like an ordinary internal call. `store`
    # scores identically to Safemath_internal. `chain`'s `s = a.add(b).sub(c)` is two internal
    # library calls in one node, s = (a + b) - c is controlled, so `s + 1` is a second target with
    # the same numbers.
    "Safemath_library": [
        ("OV", "chain", "chain", 2, 1, 0.5, 1.0, 1.0, 0, 0, 0.64, 0.64),
        ("OV", "store", "store", 2, 1, 0.5, 1.0, 1.0, 0, 0, 0.64, 0.64),
    ],
    # A public library function is a DELEGATECALL to unknown code: its result is opaque, so s is not
    # controlled and `s + 1` is not a target. No target at all -- the negative of Safemath_library.
    "Library_public": [],
    # `a - b` in outer, guarded by require(a >= b) (b = 1). Both operands are arguments, so A = 1.
    # inner's `a - b` is not a target: its result is only returned, not written or passed on.
    "Name_collision": [("OV", "outer", "outer", 4, 1, 1.0, 1.0, 1.0, 0, 1, 0.8, 0.5657)],
    # rec is inlined once from run, so the if (n == 0) gives b = 1 everywhere. The two operations
    # feeding the recursive call are targets (a call argument is a sink): `n - 1` (A = 0.5, the
    # literal 1 is not controlled) and `acc + n` (A = 1, both are parameters). `s + 1` in run reads
    # the call result, so s is controlled and A = 0.5.
    "Recursive_sum": [
        ("OV", "run", "rec", 4, 0, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
        ("OV", "run", "rec", 4, 1, 1.0, 1.0, 1.0, 0, 1, 0.8, 0.5657),
        ("OV", "run", "run", 2, 1, 0.5, 1.0, 1.0, 0, 1, 0.64, 0.4525),
    ],
}


def contract_under_test(compilation):
    """The analysed contract: the first non-library one, so library fixtures pick the user."""
    return next(c for c in compilation.slither.contracts if not c.is_library)


def targets_of(name: str) -> list:
    compilation = load(name)
    return detect(compilation, contract_under_test(compilation))


def row_of(target) -> Row:
    config = Config()
    return (
        target.vuln_class.name,
        target.entry_point.name,
        target.point.function.name,
        target.point.node.node_id,
        target.point.op_index,
        round(controllability(target), 4),
        round(exposure(target), 4),
        value_factor(target),
        target.guard_count,
        target.branch_count,
        round(risk(target, config), 4),
        round(priority(target, config), 4),
    )


@pytest.mark.parametrize("name", list(CONTROL))
def test_control_table(name: str) -> None:
    assert sorted(row_of(t) for t in targets_of(name)) == sorted(CONTROL[name])


def test_every_fixture_is_in_the_control_table() -> None:
    """A new fixture must come with hand-derived control values, not with whatever the code says."""
    assert set(CONTROL) == set(PINNED)


# ------------------------------------------------------------------ structural rules


def test_constructors_produce_no_targets() -> None:
    """`owner = msg.sender` in a constructor is Priv but can never be attacked."""
    for name in ("Owned_ctor", "Access_unprotected", "Tx_origin", "Mint_internal"):
        assert not [t for t in targets_of(name) if t.point.function.is_constructor], name


def test_dead_internal_function_produces_no_targets() -> None:
    """_burnDead has unchecked arithmetic but no public caller."""
    assert not [t for t in targets_of("Mint_internal") if t.point.function.name == "_burnDead"]


def test_internal_target_is_scored_from_the_public_caller() -> None:
    """onlyOwner on mint() protects the unguarded _mint(): g = 1, not 0."""
    for target in targets_of("Mint_internal"):
        assert target.entry_point.name == "mint"
        assert target.point.function.name == "_mint"
        assert target.guard_count == 1


# ------------------------------------------------------------------- per detector


def analysis_of(name: str) -> Analysis:
    compilation = load(name)
    return Analysis.build(compilation, compilation.slither.contracts[0])


def test_reentrancy_negatives() -> None:
    """CEI removes the write after the call; a contract without external calls has no RE."""
    for name in ("Vault_fixed_cei", "Owned_ctor", "Overflow_args"):
        assert ReentrancyDetector().detect(analysis_of(name)) == [], name


def test_lock_variable_write_produces_no_reentrancy_target() -> None:
    """`locked = false` in the modifier tail is the protection, not the flaw.

    It is read before the call and written after it, so it satisfies the static rule for SC08
    exactly; it is excluded by name, using the lock definition already needed for g(t).
    """
    analysis = analysis_of("Vault_fixed_guard")
    expansion = next(
        e for e in analysis.expansions.values() if e.entry_point.name == "withdraw"
    )
    assert {v.name for v in lock_variables(expansion)} == {"locked"}

    targets = ReentrancyDetector().detect(analysis)
    assert [t.point.function.name for t in targets] == ["withdraw"]


def test_reentrancy_needs_the_variable_read_before_the_call() -> None:
    """Unchecked_call writes `balances` after the call but never reads it before."""
    assert ReentrancyDetector().detect(analysis_of("Unchecked_call")) == []


def test_unchecked_call_negatives() -> None:
    """`require(ok)` checks the result, so Vault has no UC target."""
    for name in ("Vault", "Vault_fixed_cei", "Owned_ctor"):
        assert UncheckedCallDetector().detect(analysis_of(name)) == [], name


def test_unchecked_call_ignores_the_checked_function() -> None:
    targets = UncheckedCallDetector().detect(analysis_of("Unchecked_call"))
    assert sorted(t.entry_point.name for t in targets) == ["payout", "payoutSend"]


def test_send_produces_no_reentrancy_target() -> None:
    """2300 gas cannot pay for a storage write, so `send` is not a re-entry vector."""
    assert ReentrancyDetector().detect(analysis_of("Unchecked_call")) == []


def test_access_control_negatives() -> None:
    """V_auth is empty in Vault, and the only owner write in Overflow_args is in no function."""
    assert analysis_of("Vault").auth == set()
    assert [t.vuln_class for t in targets_of("Vault") if t.vuln_class is VulnClass.AC] == []
    assert [t.vuln_class for t in targets_of("Overflow_args") if t.vuln_class is VulnClass.AC] == []


def test_tx_origin_negative() -> None:
    """A msg.sender check is not a tx.origin check: setOwnerSender gets no TO target."""
    origin = [t for t in targets_of("Tx_origin") if t.vuln_class is VulnClass.TO]
    assert [t.entry_point.name for t in origin] == ["setOwnerOrigin"]


def test_origin_check_is_not_a_guard() -> None:
    """require(tx.origin == owner) must leave g = 0, otherwise D would hide the flaw."""
    target = next(t for t in targets_of("Tx_origin") if t.vuln_class is VulnClass.TO)
    assert target.guard_count == 0


def test_delegatecall_negative() -> None:
    for name in ("Vault", "Owned_ctor"):
        assert DelegatecallDetector().detect(analysis_of(name)) == [], name


def test_proxy_implementation_write_is_privileged() -> None:
    """`implementation` is Priv because it is a delegatecall destination, not because of V_auth."""
    analysis = analysis_of("Delegatecall_proxy")
    assert analysis.auth == set()
    assert {v.name for v in analysis.proxy_variables} == {"implementation"}


# ----------------------------------------------------------------- evaluation unit


def test_access_control_and_tx_origin_share_one_unit() -> None:
    """AC and TO are two predicates over one SWC class, so they aggregate into a single unit."""
    results = [
        _result(t)
        for t in targets_of("Tx_origin")
        if t.point.function.name == "setOwnerOrigin"
    ]
    assert len(results) == 2
    assert aggregate(results) == {
        ("SC01", "TxOrigin.setOwnerOrigin(address)"): Verdict.CONFIRMED
    }


def _result(target):
    from hsa.model import TargetResult

    return TargetResult(
        target=target,
        verdict=Verdict.CONFIRMED,
        risk=0.0,
        priority=0.0,
        budget=0.0,
        elapsed=0.0,
        time_to_verdict=0.0,
    )
