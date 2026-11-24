"""Tests for the pure logic of `experiments.pairs`: the per-evaluator aggregation and the variant-B
specificity scoring (`predicted & neg` before the confusion). None of these touch a dataset -- the
selection draw and the ground-truth negatives are exercised separately, only when SmartBugs is cloned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from experiments import baselines, metrics, pairs
from experiments.pairs import Pair, Score, aggregate_scores, score_pair


# --------------------------------------------------------------------- aggregate_scores


def _score(evaluator: str, mode: str, swc: str, conf: metrics.Confusion) -> Score:
    return Score(evaluator, mode, swc, "contract", conf)


def test_aggregate_sums_per_class_and_keeps_an_all_bucket() -> None:
    scores = [
        _score("M1", "strict", "SC08", metrics.Confusion(tn=2, fp=0)),
        _score("M1", "strict", "SC09", metrics.Confusion(tn=1, fp=1)),
    ]
    aggregated = aggregate_scores(scores)
    bucket = aggregated[("M1", "strict")]
    assert bucket["SC08"] == metrics.Confusion(tn=2, fp=0)
    assert bucket["SC09"] == metrics.Confusion(tn=1, fp=1)
    assert bucket["all"] == metrics.Confusion(tn=3, fp=1)  # summed across classes


def test_aggregate_separates_evaluators_and_modes() -> None:
    scores = [
        _score("M1", "strict", "SC08", metrics.Confusion(tn=1)),
        _score("M1", "moderate", "SC08", metrics.Confusion(fp=1)),
        _score("slither", "-", "SC08", metrics.Confusion(tn=1)),
    ]
    aggregated = aggregate_scores(scores)
    assert set(aggregated) == {("M1", "strict"), ("M1", "moderate"), ("slither", "-")}
    assert aggregated[("M1", "strict")]["all"].specificity == 1.0
    assert aggregated[("M1", "moderate")]["all"].specificity == 0.0


def test_aggregate_accumulates_same_class_across_pairs() -> None:
    scores = [
        _score("M1", "strict", "SC08", metrics.Confusion(tn=1)),
        _score("M1", "strict", "SC08", metrics.Confusion(tn=1, fp=1)),
    ]
    aggregated = aggregate_scores(scores)
    assert aggregated[("M1", "strict")]["SC08"] == metrics.Confusion(tn=2, fp=1)


# --------------------------------------------------------------------- variant-B scoring


@dataclass
class _FakeConfig:
    """Minimal stand-in: `score_pair` only reads `.symbolic_execution`."""

    symbolic_execution: bool = True


def test_score_pair_ignores_positives_outside_the_negative_universe(monkeypatch) -> None:
    """Variant B: a fixed-class positive on a function that never carried the label is not an FP.

    The negative universe is the ORIGINAL's labelled units; only a positive *on one of those* counts
    against specificity. A pre-existing finding on an unlabelled function (here `untouched`) is dropped
    by the `predicted & neg` intersection, so it neither adds a TP/FP nor removes a TN.
    """
    pair = Pair("SC08", "cei", Path("orig.sol"), Path("fixed.sol"))
    neg = {("SC08", "repaired")}

    def fake_positives(_pair, _config, mode):
        # strict: only an unlabelled finding -> must be ignored; moderate: also hits the repaired unit
        if mode == "strict":
            return {("SC08", "untouched")}
        return {("SC08", "untouched"), ("SC08", "repaired")}

    monkeypatch.setattr(pairs, "negatives", lambda _pair: neg)
    monkeypatch.setattr(pairs, "hsa_positives", fake_positives)

    def no_baseline(_pair, _tool, _timeout):
        raise baselines.BaselineUnavailable("not installed")

    monkeypatch.setattr(pairs, "baseline_positives", no_baseline)

    scores = score_pair(pair, {"M1": _FakeConfig()}, timeout=1.0)
    by_mode = {s.mode: s.confusion for s in scores}

    # strict: the unlabelled positive is dropped -> a clean true negative
    assert (by_mode["strict"].tn, by_mode["strict"].fp) == (1, 0)
    assert by_mode["strict"].specificity == 1.0
    # moderate: the positive on the repaired (labelled) unit survives the intersection -> a false positive
    assert (by_mode["moderate"].tn, by_mode["moderate"].fp) == (0, 1)
    assert by_mode["moderate"].specificity == 0.0


def test_score_pair_skips_strict_for_the_static_only_config(monkeypatch) -> None:
    """M2 has no symbolic stage, so strict is undefined (chapter 2.3) and only moderate is scored."""
    pair = Pair("SC09", "require", Path("orig.sol"), Path("fixed.sol"))
    monkeypatch.setattr(pairs, "negatives", lambda _pair: {("SC09", "run")})
    monkeypatch.setattr(pairs, "hsa_positives", lambda *_: set())

    def no_baseline(_pair, _tool, _timeout):
        raise baselines.BaselineUnavailable("not installed")

    monkeypatch.setattr(pairs, "baseline_positives", no_baseline)

    scores = score_pair(pair, {"M2": _FakeConfig(symbolic_execution=False)}, timeout=1.0)
    assert [s.mode for s in scores] == ["moderate"]


def test_score_pair_scores_an_available_baseline(monkeypatch) -> None:
    """A baseline that runs is scored once (mode '-'); its positives are intersected with neg too."""
    pair = Pair("SC01", "modifier", Path("orig.sol"), Path("fixed.sol"))
    neg = {("SC01", "changeOwner")}
    monkeypatch.setattr(pairs, "negatives", lambda _pair: neg)
    monkeypatch.setattr(pairs, "hsa_positives", lambda *_: set())

    def baseline(_pair, tool, _timeout):
        if tool == "slither":
            return {("SC01", "changeOwner"), ("SC01", "elsewhere")}  # elsewhere dropped by & neg
        raise baselines.BaselineUnavailable("mythril not installed")

    monkeypatch.setattr(pairs, "baseline_positives", baseline)

    scores = score_pair(pair, {}, timeout=1.0)
    (slither,) = [s for s in scores if s.evaluator == "slither"]
    assert slither.mode == "-"
    assert (slither.confusion.tn, slither.confusion.fp) == (0, 1)  # only the labelled hit counts
