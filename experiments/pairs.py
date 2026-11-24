"""The fixed-version pairs (chapter 2.3): the only source of true negatives in the evaluation.

Every labelled contract of the samples is vulnerable, so Precision / Recall alone cannot say whether
the method is quiet on safe code. The pairs fix that: for 32 vulnerable SmartBugs contracts a repaired
version is written by hand, and the fixed-class unit on it should be a true negative (REFUTED, or no
target at all). Specificity Spec = TN / (TN + FP) on those units -- in strict and moderate -- is the
headline pair result.

The design is fixed by chapter 2.3:

* **32 pairs, SmartBugs Curated only.** SolidiFI injects dozens of bugs per file, so "fixing" one
  would be rewriting the contract; its pairs would not be comparable.
* **8 per class** SC01, SC06, SC08, SC09, drawn with the experiment seed from the compilable contracts
  of that class (the same candidate pool `experiments.sample` draws the main sample from, so the
  exclusions carry over).
* **two fix styles, 4 contracts each**, so each pair exercises a different branch of the class
  predicate on real code:
  - SC08 reentrancy -- `cei` (write before the call) / `guard` (a nonReentrant lock variable);
  - SC09 overflow -- `require` (explicit bound check) / `safemath` (a checked internal call, inlined);
  - SC06 unchecked call -- `require` (`require(ok)`) / `revert` (`if (!ok) revert()`);
  - SC01 access control -- `modifier` (an onlyOwner modifier) / `require` (`require(msg.sender ==
    owner)` in the body).
* **only the fixed class is scored** on the repaired version: a pre-0.8 overflow target left in a
  repaired reentrancy contract is not a pair false positive (chapter 2.3).
* **the solc version is inherited from the original** -- the fixed file keeps the original pragma, so
  `prep.compile_contract` pins the same compiler and the difference cannot come from the toolchain.

This module only *selects and locates* the pairs deterministically; the fixed `.sol` files are written
by hand under `experiments/pairs/<category>/<style>/`, and the runner that scores them against every
configuration and the baselines lives alongside once the fixtures exist.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from experiments import baselines, metrics
from experiments.configs import SEED, modes
from experiments.datasets import SMARTBUGS
from experiments.sample import Case, _candidates
from hsa.cli import analyze
from hsa.config import Config, VulnClass
from hsa.prep import compile_contract

#: Pairs drawn per class, and how the 8 split across the two fix styles (chapter 2.3).
PAIRS_PER_CLASS = 8
PER_STYLE = 4

#: The four scored classes, in a fixed order so the shared RNG draw is reproducible.
PAIR_CLASSES: tuple[str, ...] = ("SC01", "SC06", "SC08", "SC09")

#: Class -> the SmartBugs category whose compilable contracts are the candidate pool.
CATEGORY: dict[str, str] = {
    "SC01": "access_control",
    "SC06": "unchecked_low_level_calls",
    "SC08": "reentrancy",
    "SC09": "arithmetic",
}

#: Class -> the two fix styles, first four drawn contracts take the first style, next four the second.
FIX_STYLES: dict[str, tuple[str, str]] = {
    "SC01": ("modifier", "require"),
    "SC06": ("require", "revert"),
    "SC08": ("cei", "guard"),
    "SC09": ("require", "safemath"),
}

#: Where the hand-written fixed versions live.
PAIRS_DIR = Path("experiments/pairs")

#: The measurement run, used to narrow each candidate pool to contracts where the static stage
#: actually produces a target of the class (chapter 2.3 selection, option B). Pinned and committed, so
#: the draw is reproducible without re-running the engine.
COVERAGE = Path("experiments/coverage.json")


@dataclass(frozen=True)
class Pair:
    """One original/fixed contract pair."""

    swc: str  # the fixed class, the only one scored on the fixed version
    style: str  # the fix style applied
    original: Path  # the vulnerable SmartBugs contract
    fixed: Path  # the hand-written repaired version

    @property
    def name(self) -> str:
        return self.original.stem

    def fixed_exists(self) -> bool:
        return self.fixed.is_file()


def _fixed_path(swc: str, style: str, original: Path) -> Path:
    return PAIRS_DIR / CATEGORY[swc] / style / original.name


#: Originals that are REFUTED for their class on the ORIGINAL under M1, so the pair is degenerate: the
#: method already calls the original safe, and a correct fix would prove nothing. They are replaced by
#: the next seed-order candidate of the same class, keeping the fix style (chapter 2.3, variant c of the
#: deferred-changes decision). UNKNOWN originals are kept -- for SC09 almost all originals are UNKNOWN by
#: design (the OV strong condition is an exists-forall the solver often cannot close under budget), and a
#: UNKNOWN is a positive in the moderate mode, so those pairs still test the fix.
DEGENERATE: frozenset[str] = frozenset({"access_control/arbitrary_location_write_simple.sol"})


def _relkey(path: Path) -> str:
    return path.resolve().relative_to(SMARTBUGS.contracts.resolve()).as_posix()


@lru_cache(maxsize=1)
def _classes_by_contract() -> dict[str, set[str]]:
    """Each measured contract's path -> the SWC codes its static targets belong to.

    Read from `coverage.json`: a target carries a `VulnClass` name (RE, AC, ...), reduced here to its
    SWC so the pool filter speaks the same language as the sample labels.
    """
    payload = json.loads(COVERAGE.read_text(encoding="utf-8"))
    by_contract: dict[str, set[str]] = {}
    for report in payload["contracts"]:
        swcs = {VulnClass[t["class"]].swc for t in report["targets"]}
        by_contract[Path(report["path"]).as_posix()] = swcs
    return by_contract


def _pool(swc: str) -> list[Path]:
    """Candidates of the class whose static stage actually produces a target of that class (option B).

    The literal rule of 2.3 is "contracts labelled with the class"; this narrows it to those the method
    also raises the class on, so a fix to that class is meaningful rather than a no-op. The narrowing is
    recorded in the deferred-changes log for the thesis text.
    """
    by_contract = _classes_by_contract()
    return [
        path
        for path in _candidates(SMARTBUGS, CATEGORY[swc])
        if swc in by_contract.get(path.as_posix(), set())
    ]


def selection() -> list[Pair]:
    """The 32 pairs, drawn deterministically from the experiment seed.

    One `random.Random(SEED)` is drawn from in the fixed class order `PAIR_CLASSES`; within a class the
    8 drawn contracts are sorted and the first `PER_STYLE` take the first fix style, the rest the
    second. Sorting before the split makes the style assignment independent of the draw order, so it is
    stable even if `random`'s internals ever change the order `sample` returns.
    """
    rng = random.Random(SEED)
    pairs: list[Pair] = []
    for swc in PAIR_CLASSES:
        pool = _pool(swc)
        chosen = sorted(rng.sample(pool, PAIRS_PER_CLASS))
        style_a, style_b = FIX_STYLES[swc]
        styled = [
            (original, style_a if index < PER_STYLE else style_b)
            for index, original in enumerate(chosen)
        ]
        for original, style in _substitute(pool, styled):
            pairs.append(Pair(swc, style, original, _fixed_path(swc, style, original)))
    return pairs


def _substitute(pool: list[Path], styled: list[tuple[Path, str]]) -> list[tuple[Path, str]]:
    """Swap degenerate originals for the next seed-order candidate, keeping each surviving pick's style.

    The shared draw in `selection` is left untouched (so the other classes are unaffected); only the
    degenerate contracts of this class are replaced, and each takes a replacement in its own style slot
    so the modifier/require split of the survivors does not shift. "Next by seed" is the first candidate
    of a fresh seed permutation of the pool that is neither already chosen nor itself degenerate, so the
    substitution is deterministic (chapter 2.3, variant c).
    """
    if not any(_relkey(original) in DEGENERATE for original, _ in styled):
        return styled
    taken = {original for original, _ in styled}
    order = iter(random.Random(SEED).sample(pool, len(pool)))
    result: list[tuple[Path, str]] = []
    for original, style in styled:
        if _relkey(original) not in DEGENERATE:
            result.append((original, style))
            continue
        for candidate in order:
            if candidate not in taken and _relkey(candidate) not in DEGENERATE:
                taken.add(candidate)
                result.append((candidate, style))
                break
    return result


# ==================================================================== scoring (specificity, variant 1)

#: The two decision modes of chapter 2.3. For the method a unit is positive if its strongest verdict
#: is CONFIRMED (strict) or CONFIRMED/UNKNOWN (moderate); the baselines are mode-independent.
MODES: tuple[str, ...] = ("strict", "moderate")
_ALLOWED: dict[str, set[str]] = {"strict": {"CONFIRMED"}, "moderate": {"CONFIRMED", "UNKNOWN"}}


def negatives(pair: Pair) -> set[tuple[str, str]]:
    """The specificity's negative universe for one pair (variant 1).

    The functions carrying the fixed class's ground-truth label in the ORIGINAL contract, as
    `(swc, function)` units. This is a *common* universe: it comes from the dataset labels, not from
    any tool's output, so the method and both baselines are scored against the same negatives. Only
    the fixed class is scored, so labels of other classes are dropped (chapter 2.3). A correct fix
    turns each of these into a true negative; a fixed-class positive *on one of these units* is a
    false positive. Fixed-class positives on functions outside this universe (a pre-existing finding
    the fix never touched) are ignored here -- they belong to the manual FP review on the main sample,
    not to the repair's specificity (chapter 2.3, variant B of the deferred-changes decision).
    """
    case = Case(SMARTBUGS.name, pair.original, CATEGORY[pair.swc], pair.swc)
    compilation = compile_contract(pair.original)
    truth = metrics.ground_truth(case, compilation)
    return {(swc, function) for swc, function in truth.units if swc == pair.swc}


def hsa_positives(pair: Pair, config: Config, mode: str) -> set[tuple[str, str]]:
    """The method's fixed-class positive units on the repaired version, under one config and mode."""
    report = analyze(pair.fixed, config)
    allowed = _ALLOWED[mode]
    return {
        unit
        for unit, verdict in report.units.items()
        if unit[0] == pair.swc and verdict.value in allowed
    }


def baseline_positives(pair: Pair, tool: str, timeout: float) -> set[tuple[str, str]]:
    """A baseline's fixed-class positive units on the repaired version."""
    runner = baselines.run_slither if tool == "slither" else baselines.run_mythril
    report = runner(pair.fixed, timeout)
    return {(swc, function) for swc, function in report.units() if swc == pair.swc}


@dataclass(frozen=True)
class Score:
    """One evaluator's confusion on one pair (variant-1 specificity)."""

    evaluator: str  # a config mode value (M1..M4) or a baseline tool name
    mode: str  # strict / moderate for the method, "-" for the baselines
    swc: str
    name: str  # the pair's contract stem
    confusion: metrics.Confusion


def score_pair(pair: Pair, configs: dict[str, Config], timeout: float) -> list[Score]:
    """Score one pair with every method config (both modes) and both baselines.

    The fixed version must exist; callers skip pairs whose fixture is not yet written. The negative
    universe is computed once per pair and shared by every evaluator so the specificity is comparable.
    """
    neg = negatives(pair)
    scores: list[Score] = []
    for name, config in configs.items():
        for mode in MODES:
            if not config.symbolic_execution and mode == "strict":
                continue  # M2 has no symbolic stage: strict is undefined (chapter 2.3)
            predicted = hsa_positives(pair, config, mode) & neg
            scores.append(Score(name, mode, pair.swc, pair.name,
                                metrics.confusion(predicted, set(), neg)))
    for tool in ("slither", "mythril"):
        try:
            predicted = baseline_positives(pair, tool, timeout) & neg
        except baselines.BaselineUnavailable:
            continue
        scores.append(Score(tool, "-", pair.swc, pair.name,
                            metrics.confusion(predicted, set(), neg)))
    return scores


def aggregate_scores(scores: list[Score]) -> dict[tuple[str, str], dict[str, metrics.Confusion]]:
    """Sum confusions per (evaluator, mode), both per class and over all classes ('all').

    Returns `{(evaluator, mode): {swc or 'all': Confusion}}`, so the driver can print specificity per
    class and the headline macro/overall figure.
    """
    out: dict[tuple[str, str], dict[str, metrics.Confusion]] = {}
    for score in scores:
        bucket = out.setdefault((score.evaluator, score.mode), {})
        bucket[score.swc] = bucket.get(score.swc, metrics.Confusion()) + score.confusion
        bucket["all"] = bucket.get("all", metrics.Confusion()) + score.confusion
    return out


def run(configs: dict[str, Config], timeout: float) -> list[Score]:
    """Score every pair whose fixed version exists."""
    scores: list[Score] = []
    for pair in selection():
        if pair.fixed_exists():
            scores.extend(score_pair(pair, configs, timeout))
    return scores


# ==================================================================== drivers


def _list() -> int:
    pairs = selection()
    current = None
    for pair in pairs:
        if pair.swc != current:
            current = pair.swc
            print(f"\n== {pair.swc} ({CATEGORY[pair.swc]}) ==")
        mark = "ok" if pair.fixed_exists() else "--"
        print(f"  [{mark}] {pair.style:<9} {pair.name}")
    missing = [p for p in pairs if not p.fixed_exists()]
    print(f"\n{len(pairs)} pairs, {len(missing)} fixed versions still to write")
    return 0


def _score(out: Path, timeout: float) -> int:
    configs = modes()
    scores = run(configs, timeout)
    aggregated = aggregate_scores(scores)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            [
                {
                    "evaluator": s.evaluator,
                    "mode": s.mode,
                    "swc": s.swc,
                    "contract": s.name,
                    "confusion": {"tp": s.confusion.tp, "fp": s.confusion.fp,
                                  "fn": s.confusion.fn, "tn": s.confusion.tn},
                }
                for s in scores
            ],
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"{'evaluator':<12}{'mode':<10}{'specificity':>12}  (TN/(TN+FP), by class)")
    for (evaluator, mode), by_class in sorted(aggregated.items()):
        overall = by_class["all"]
        spec = overall.specificity
        per = " ".join(
            f"{swc}={by_class[swc].specificity:.2f}"
            for swc in PAIR_CLASSES
            if swc in by_class and by_class[swc].specificity is not None
        )
        spec_text = f"{spec:.3f}" if spec is not None else "-"
        print(f"{evaluator:<12}{mode:<10}{spec_text:>12}  fp={overall.fp} tn={overall.tn}  {per}")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="show the 32 pairs and which fixed versions exist (default)")
    score = sub.add_parser("score", help="score the written pairs for specificity")
    score.add_argument("--out", type=Path, default=Path("experiments/runs/pairs.json"))
    score.add_argument("--timeout", type=float, default=Config.budget,
                       help="seconds per contract for the baselines")
    arguments = parser.parse_args(argv)

    if arguments.command == "score":
        return _score(arguments.out, arguments.timeout)
    return _list()


if __name__ == "__main__":
    raise SystemExit(main())
