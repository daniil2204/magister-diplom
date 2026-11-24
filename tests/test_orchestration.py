"""Tests for the per-contract orchestration of `hsa.symexec.engine.analyze_targets` (week 4).

Unlike `test_engine`, which drives one target through the real solver, these tests pin down the
queue itself: the P(t) order, the budget B_t carried along the queue as a shared pool (2.18), the
skipping of a node already CONFIRMED from another entry point, and the M4 seeded order. To keep
them deterministic and fast they inject a scripted `runner` in place of the real single-target
search, so no solver or wall clock is involved.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from hsa.config import Config, Mode
from hsa.model import UnknownReason, Verdict
from hsa.priority import budgets, order, priority
from hsa.static import DETECTORS
from hsa.static.base import Analysis
from hsa.symexec.engine import analyze_targets
from hsa.symexec.predicates import Outcome
from tests.conftest import load


def _targets(name: str):
    compilation = load(name)
    contract = next(c for c in compilation.slither.contracts if not c.is_library)
    analysis = Analysis.build(compilation, contract)
    targets = [t for detector in DETECTORS for t in detector.detect(analysis)]
    return analysis, targets


def _pairs(name: str):
    analysis, targets = _targets(name)
    return [(analysis, target) for target in targets]


def recording_runner(outcome_for=None, elapsed_for=None):
    """A stand-in for `_run_target` that records every (target, budget) it is handed.

    `outcome_for(target)` chooses the verdict (default REFUTED); `elapsed_for(target, budget)`
    chooses how much of the pool the call consumes (default 0.0, i.e. the target finishes instantly).
    """
    calls = []

    def run(analysis, target, config, budget):
        calls.append(SimpleNamespace(target=target, budget=budget))
        outcome = outcome_for(target) if outcome_for else Outcome(Verdict.REFUTED)
        elapsed = elapsed_for(target, budget) if elapsed_for else 0.0
        return outcome, elapsed

    run.calls = calls
    return run


# ------------------------------------------------------------------- queue order


def test_queue_runs_targets_in_descending_priority() -> None:
    config = Config(mode=Mode.M1)
    runner = recording_runner()
    analyze_targets(_pairs("Overflow_mul"), config, runner=runner)
    priorities = [priority(call.target, config) for call in runner.calls]
    assert priorities == sorted(priorities, reverse=True)


def test_m4_order_is_reproducible_from_the_seed() -> None:
    pairs = _pairs("Overflow_mul")
    first, second = recording_runner(), recording_runner()
    analyze_targets(pairs, Config(mode=Mode.M4, seed=7), runner=first)
    analyze_targets(pairs, Config(mode=Mode.M4, seed=7), runner=second)
    assert [id(c.target) for c in first.calls] == [id(c.target) for c in second.calls]
    assert {id(c.target) for c in first.calls} == {id(t) for _, t in pairs}


# ------------------------------------------------------------------- M2


def test_m2_never_runs_the_engine() -> None:
    runner = recording_runner()
    results = analyze_targets(_pairs("Overflow_mul"), Config(mode=Mode.M2), runner=runner)
    assert runner.calls == []
    assert all(r.verdict is Verdict.UNKNOWN for r in results)
    assert all(r.reason is UnknownReason.STATIC_ONLY for r in results)


# ------------------------------------------------------------------- budget carry / bank (2.18)


def test_unused_budget_is_carried_forward_to_a_later_target() -> None:
    """A target that finishes early banks its remaining B_t; a later target may spend past its own."""
    config = Config(mode=Mode.M1)
    pairs = _pairs("Overflow_mul")
    allocation = budgets(order([t for _, t in pairs], config), config)
    # Every target finishes instantly, so the bank is the sum of the earlier targets' B_t.
    runner = recording_runner(elapsed_for=lambda t, b: 0.0)
    analyze_targets(pairs, config, runner=runner)
    bank = 0.0
    for call in runner.calls:
        base = allocation[id(call.target)]
        assert call.budget == pytest.approx(min(base + bank, config.budget))
        bank += base  # elapsed is 0, so the whole B_t is carried forward
    assert bank > allocation[id(runner.calls[0].target)]  # the bank really did accumulate


def test_each_grant_is_capped_by_the_whole_file_budget() -> None:
    """grant = min(B_t + bank, budget - spent); spent and bank track time actually used."""
    config = Config(mode=Mode.M1)
    pairs = _pairs("Overflow_mul")
    allocation = budgets(order([t for _, t in pairs], config), config)
    runner = recording_runner(elapsed_for=lambda t, b: 50.0)
    analyze_targets(pairs, config, runner=runner)
    spent, bank = 0.0, 0.0
    for call in runner.calls:
        base = allocation[id(call.target)]
        assert call.budget == pytest.approx(min(base + bank, config.budget - spent))
        spent += 50.0
        bank = max(0.0, bank + base - 50.0)


def test_budget_exhaustion_leaves_the_tail_budget_exhausted() -> None:
    config = Config(mode=Mode.M1)
    pairs = _pairs("Overflow_mul")
    runner = recording_runner(elapsed_for=lambda t, b: 10_000.0)  # the first target drains the budget
    results = analyze_targets(pairs, config, runner=runner)
    assert len(runner.calls) == 1
    tail = results[1:]
    assert tail
    assert all(r.reason is UnknownReason.BUDGET_EXHAUSTED for r in tail)
    assert all(r.elapsed == 0.0 for r in tail)


# ------------------------------------------------------------------- skip confirmed


def test_a_confirmed_node_is_skipped_from_another_entry_point() -> None:
    analysis, targets = _targets("Mint_internal")
    first = targets[0]
    other = next(
        f for f in analysis.contract.functions if f.canonical_name != first.entry_point.canonical_name
    )
    clone = dataclasses.replace(
        first, context=dataclasses.replace(first.context, entry_point=other)
    )
    assert clone.node_key == first.node_key  # same (class, node), different entry point

    runner = recording_runner(outcome_for=lambda t: Outcome(Verdict.CONFIRMED))
    results = analyze_targets([(analysis, first), (analysis, clone)], Config(mode=Mode.M1), runner=runner)
    assert len(runner.calls) == 1  # the second target was skipped, not re-analysed
    assert sum(r.verdict is Verdict.CONFIRMED for r in results) == 1
    skipped = [r for r in results if r.reason is UnknownReason.SKIPPED_CONFIRMED]
    assert len(skipped) == 1
    assert skipped[0].elapsed == 0.0


def test_a_refuted_node_is_not_skipped() -> None:
    """A refutation from one entry point says nothing about another, so both are analysed."""
    analysis, targets = _targets("Mint_internal")
    first = targets[0]
    other = next(
        f for f in analysis.contract.functions if f.canonical_name != first.entry_point.canonical_name
    )
    clone = dataclasses.replace(
        first, context=dataclasses.replace(first.context, entry_point=other)
    )
    runner = recording_runner(outcome_for=lambda t: Outcome(Verdict.REFUTED))
    analyze_targets([(analysis, first), (analysis, clone)], Config(mode=Mode.M1), runner=runner)
    assert len(runner.calls) == 2
