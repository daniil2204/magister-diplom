"""Tests for the pure functions of `experiments.metrics`: scoring, the offline replay and the two
statistical tests. None of these need a dataset -- the ground-truth loader is exercised separately,
only when the datasets are cloned.
"""

from __future__ import annotations

import math

import pytest

from experiments.configs import BASE
from hsa.config import Mode
from experiments.metrics import (
    Confusion,
    confusion,
    delta_fp,
    macro,
    mcnemar_exact,
    micro,
    per_class,
    positives,
    recall_at,
    replay,
    unit_verdicts,
    wilcoxon_signed_rank,
)

# --------------------------------------------------------------------- Confusion math


def test_confusion_metrics_on_a_populated_cell() -> None:
    conf = Confusion(tp=3, fp=1, fn=1, tn=2)
    assert conf.precision == 0.75
    assert conf.recall == 0.75
    assert conf.f1 == pytest.approx(0.75)
    assert conf.specificity == pytest.approx(2 / 3)


def test_confusion_is_none_when_a_denominator_is_empty() -> None:
    empty = Confusion()
    assert empty.precision is None
    assert empty.recall is None
    assert empty.f1 is None  # nothing predicted and nothing to find -> undefined, not zero
    assert empty.specificity is None


def test_confusion_f1_is_zero_when_there_are_units_but_no_overlap() -> None:
    conf = Confusion(tp=0, fp=1, fn=1)
    assert conf.precision == 0.0
    assert conf.recall == 0.0
    assert conf.f1 == 0.0  # defined (there are units) but the harmonic mean collapses to 0


def test_confusion_adds_componentwise() -> None:
    assert Confusion(1, 2, 3, 4) + Confusion(10, 20, 30, 40) == Confusion(11, 22, 33, 44)


# --------------------------------------------------------------------- confusion / per_class


def test_confusion_counts_against_the_truth() -> None:
    predicted = {("SC08", "f"), ("SC06", "g")}
    truth = {("SC08", "f"), ("SC09", "h")}
    conf = confusion(predicted, truth)
    assert (conf.tp, conf.fp, conf.fn, conf.tn) == (1, 1, 1, 0)


def test_confusion_uses_negatives_only_for_specificity() -> None:
    """The pairs supply negatives (fixed-class units); TN is counted against them."""
    predicted = {("SC08", "bad")}
    truth: set = set()
    negatives = {("SC08", "fixed_a"), ("SC08", "fixed_b")}
    conf = confusion(predicted, truth, negatives=negatives)
    assert conf.tn == 2 and conf.fp == 1


def test_per_class_splits_by_swc_not_by_function() -> None:
    predicted = {("SC08", "f"), ("SC09", "g")}
    truth = {("SC08", "f"), ("SC09", "x")}
    by_class = per_class(predicted, truth)
    assert by_class["SC08"] == Confusion(tp=1)
    assert by_class["SC09"] == Confusion(tp=0, fp=1, fn=1)
    assert by_class["SC01"] == Confusion()  # a class with no units at all


# --------------------------------------------------------------------- macro / micro


def test_macro_averages_only_defined_classes() -> None:
    by_class = {
        "SC01": Confusion(tp=1, fp=1, fn=0),  # precision 0.5, recall 1.0
        "SC06": Confusion(tp=1, fp=0, fn=1),  # precision 1.0, recall 0.5
        "SC08": Confusion(),  # undefined -> ignored in every average
        "SC09": Confusion(tp=2, fp=0, fn=0),  # precision 1.0, recall 1.0
    }
    averaged = macro(by_class)
    assert averaged["precision"] == pytest.approx((0.5 + 1.0 + 1.0) / 3)
    assert averaged["recall"] == pytest.approx((1.0 + 0.5 + 1.0) / 3)


def test_macro_is_none_when_every_class_is_undefined() -> None:
    assert macro({"SC01": Confusion(), "SC06": Confusion()})["precision"] is None


def test_micro_sums_the_cells() -> None:
    by_class = {"SC01": Confusion(1, 2, 3, 4), "SC06": Confusion(10, 20, 30, 40)}
    assert micro(by_class) == Confusion(11, 22, 33, 44)


def test_delta_fp_is_the_refuted_share() -> None:
    assert delta_fp(fp_m1=2, fp_m2=10) == pytest.approx(0.8)
    assert delta_fp(fp_m1=0, fp_m2=0) is None  # no static false warnings -> undefined


# --------------------------------------------------------------------- verdict aggregation


def test_unit_verdicts_keeps_the_strongest_verdict() -> None:
    targets = [
        {"swc": "SC08", "function": "f", "verdict": "REFUTED"},
        {"swc": "SC08", "function": "f", "verdict": "CONFIRMED"},  # wins
        {"swc": "SC06", "function": "g", "verdict": "UNKNOWN"},
    ]
    verdicts = unit_verdicts(targets)
    assert verdicts[("SC08", "f")] == "CONFIRMED"
    assert verdicts[("SC06", "g")] == "UNKNOWN"


def test_positives_differ_by_mode() -> None:
    verdicts = {
        ("SC08", "f"): "CONFIRMED",
        ("SC06", "g"): "UNKNOWN",
        ("SC09", "h"): "REFUTED",
    }
    assert positives(verdicts, "strict") == {("SC08", "f")}
    assert positives(verdicts, "moderate") == {("SC08", "f"), ("SC06", "g")}


# --------------------------------------------------------------------- offline replay


def _static(target_id: str, *, severity, A, D, M, b) -> dict:
    return {
        "target_id": target_id,
        "severity": severity,
        "controllability": A,
        "exposure": D,
        "value_factor": M,
        "branch_count": b,
    }


def _ref(target_id, swc, function, verdict, time_to_verdict, reason=None) -> dict:
    return {
        "swc": swc,
        "function": function,
        "verdict": verdict,
        "reason": reason,
        "time_to_verdict": time_to_verdict,
    }


def test_replay_confirms_both_when_the_budget_is_ample() -> None:
    statics = [
        _static("RE|E|f|1|0", severity=1.0, A=0.5, D=1.0, M=1.0, b=2),  # P ~ 0.462
        _static("OV|E|g|2|0", severity=0.8, A=1.0, D=1.0, M=1.0, b=0),  # P = 0.8, goes first
    ]
    reference = {
        "RE|E|f|1|0": _ref("RE|E|f|1|0", "SC08", "f", "CONFIRMED", 10.0),
        "OV|E|g|2|0": _ref("OV|E|g|2|0", "SC09", "g", "CONFIRMED", 5.0),
    }
    replayed = replay(statics, reference, BASE, static_elapsed=1.0)
    by_id = {r["target_id"]: r for r in replayed}
    # the higher-priority OV target is processed first
    assert [r["target_id"] for r in replayed] == ["OV|E|g|2|0", "RE|E|f|1|0"]
    assert by_id["OV|E|g|2|0"]["verdict"] == "CONFIRMED"
    assert by_id["RE|E|f|1|0"]["verdict"] == "CONFIRMED"
    # time_to_verdict counts from the contract start: static (1.0) + cumulative spend
    assert by_id["OV|E|g|2|0"]["time_to_verdict"] == pytest.approx(6.0)  # 1 + 5
    assert by_id["RE|E|f|1|0"]["time_to_verdict"] == pytest.approx(16.0)  # 1 + 5 + 10


def test_replay_times_out_when_reference_time_exceeds_the_grant() -> None:
    statics = [_static("OV|E|g|2|0", severity=0.8, A=1.0, D=1.0, M=1.0, b=0)]
    reference = {"OV|E|g|2|0": _ref("OV|E|g|2|0", "SC09", "g", "CONFIRMED", 400.0)}
    (result,) = replay(statics, reference, BASE)
    assert result["verdict"] == "UNKNOWN"
    assert result["reason"] == "timeout"


def test_replay_skips_a_node_already_confirmed_from_another_entry_point() -> None:
    """Same (class, function, node), two entry points: the second is skipped, not re-analysed."""
    statics = [
        _static("RE|E1|f|1|0", severity=1.0, A=0.5, D=1.0, M=1.0, b=2),
        _static("RE|E2|f|1|0", severity=1.0, A=0.5, D=1.0, M=1.0, b=2),
    ]
    reference = {
        "RE|E1|f|1|0": _ref("RE|E1|f|1|0", "SC08", "f", "CONFIRMED", 3.0),
        "RE|E2|f|1|0": _ref("RE|E2|f|1|0", "SC08", "f", "CONFIRMED", 3.0),
    }
    replayed = replay(statics, reference, BASE)
    by_id = {r["target_id"]: r for r in replayed}
    # E1 sorts before E2 at equal priority, so E1 confirms and E2 is skipped
    assert by_id["RE|E1|f|1|0"]["verdict"] == "CONFIRMED"
    assert by_id["RE|E2|f|1|0"]["verdict"] == "UNKNOWN"
    assert by_id["RE|E2|f|1|0"]["reason"] == "skipped_confirmed"


def test_replay_marks_budget_exhausted_once_the_queue_runs_out_of_time() -> None:
    tiny = BASE.with_(budget=1.0)
    statics = [
        _static("OV|E|g|2|0", severity=0.8, A=1.0, D=1.0, M=1.0, b=0),  # first
        _static("RE|E|f|1|0", severity=1.0, A=0.5, D=1.0, M=1.0, b=2),
    ]
    reference = {
        "OV|E|g|2|0": _ref("OV|E|g|2|0", "SC09", "g", "CONFIRMED", 5.0),
        "RE|E|f|1|0": _ref("RE|E|f|1|0", "SC08", "f", "CONFIRMED", 5.0),
    }
    replayed = replay(statics, reference, tiny)
    by_id = {r["target_id"]: r for r in replayed}
    assert by_id["OV|E|g|2|0"]["reason"] == "timeout"  # grant capped at the 1 s budget
    assert by_id["RE|E|f|1|0"]["reason"] == "budget_exhausted"  # the queue never reached it


def test_replay_uses_a_seeded_order_under_m4() -> None:
    """M4 drops priority ordering; the order is a seeded shuffle, deterministic across runs."""
    statics = [
        _static(f"OV|E|g|{i}|0", severity=0.8, A=1.0, D=1.0, M=1.0, b=0) for i in range(6)
    ]
    reference = {
        s["target_id"]: _ref(s["target_id"], "SC09", f"g{i}", "REFUTED", 0.1)
        for i, s in enumerate(statics)
    }
    m4 = BASE.with_(mode=Mode.M4)
    first = [r["target_id"] for r in replay(statics, reference, m4)]
    second = [r["target_id"] for r in replay(statics, reference, m4)]
    assert first == second  # reproducible from the seed


# --------------------------------------------------------------------- Recall(tau)


def test_recall_at_counts_only_timely_confirmations() -> None:
    replayed = [
        {"swc": "SC08", "function": "f", "verdict": "CONFIRMED", "time_to_verdict": 8.0},
        {"swc": "SC06", "function": "g", "verdict": "CONFIRMED", "time_to_verdict": 40.0},
        {"swc": "SC09", "function": "h", "verdict": "REFUTED", "time_to_verdict": 1.0},
    ]
    truth = {("SC08", "f"), ("SC06", "g"), ("SC09", "h")}
    assert recall_at(replayed, truth, 10.0) == pytest.approx(1 / 3)  # only f in time
    assert recall_at(replayed, truth, 60.0) == pytest.approx(2 / 3)  # f and g, never the refuted h
    assert recall_at(replayed, set(), 60.0) is None  # no truth -> undefined


# --------------------------------------------------------------------- statistics


def test_mcnemar_is_one_when_discordant_pairs_are_balanced() -> None:
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(5, 5) == 1.0  # symmetric, two-sided tail exceeds 1 and is clamped


def test_mcnemar_is_small_when_all_discordance_is_one_sided() -> None:
    assert mcnemar_exact(10, 0) == pytest.approx(2 * (1 / 2 ** 10))
    assert mcnemar_exact(1, 0) == 1.0  # a single discordant pair cannot be significant


def test_wilcoxon_detects_a_consistent_shift() -> None:
    xs = [float(v) for v in range(10, 110, 10)]  # 10..100
    ys = [0.0] * 10
    p = wilcoxon_signed_rank(xs, ys)
    assert p is not None and 0.0 < p < 0.01


def test_wilcoxon_is_none_when_every_pair_is_tied() -> None:
    assert wilcoxon_signed_rank([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) is None


def test_wilcoxon_matches_the_normal_approximation_by_hand() -> None:
    xs = [float(v) for v in range(10, 110, 10)]
    ys = [0.0] * 10
    # all 10 differences positive and distinct: w+ = 55, mean = 27.5, var = 96.25
    z = (55 - 27.5) / math.sqrt(96.25)
    expected = math.erfc(abs(z) / math.sqrt(2))
    assert wilcoxon_signed_rank(xs, ys) == pytest.approx(expected)
