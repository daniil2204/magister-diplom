"""The experimental sample -- chapter 2.3, variant A: 147 contracts.

The two datasets are drawn differently because they are shaped differently:

* **SmartBugs Curated** holds a few dozen small, hand-picked contracts per class, so ALL compilable
  contracts of the four sampled categories are taken -- 17 + 15 + 29 + 51 = 112. Nothing is drawn at
  random: the whole category is the sample.
* **SolidiFI** injects dozens of bugs into large contracts and has 50 compilable files per type, so
  taking all of them would drown SmartBugs and tilt every pooled number toward SolidiFI. Instead a
  FIXED number per type is drawn with the experiment seed: 7 x 5 = 35.

112 + 35 = 147, the count the author approved. The class skew that remains (OV dominates, because the
pre-0.8 code makes almost every addition a target) is a property of the method, not fixed by throwing
data away; chapter 3 neutralises it by macro-averaging over SWC classes.

Compilability is NOT decided here by compiling -- that is slow and already measured. The four
contracts `experiments/datasets.md` excludes are listed in `EXCLUDED`, and `verify()` cross-checks
the whole sample against `coverage.json` so a drift between this list and the measured run is caught
rather than silently shipped.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

from experiments import mapping
from experiments.configs import SEED
from experiments.datasets import SMARTBUGS, SOLIDIFI, Dataset

#: Contracts drawn per SolidiFI bug type (chapter 2.3, variant A).
SOLIDIFI_PER_TYPE = 7

#: The four contracts `experiments/datasets.md` excludes, keyed by dataset name and listed by the
#: path relative to the dataset's contracts directory. Three are slither-analyzer limitations, one is
#: a compiler version below the supported window. An excluded contract is in no configuration's
#: sample, baselines included.
EXCLUDED: dict[str, frozenset[str]] = {
    SMARTBUGS.name: frozenset(
        {
            "access_control/parity_wallet_bug_1.sol",
            "reentrancy/reentrancy_bonus.sol",
            "reentrancy/reentrancy_cross_function.sol",
            "unchecked_low_level_calls/0x89c1b3807d4c67df034fffb62f3509561218d30b.sol",
        }
    ),
    SOLIDIFI.name: frozenset(),
}


@dataclass(frozen=True)
class Case:
    """One contract in the sample, carrying the label it was drawn under."""

    dataset: str
    path: Path
    #: The dataset's own label -- a SmartBugs category or a SolidiFI bug type.
    label: str
    #: The method SWC class that label maps to (`experiments.mapping`).
    swc: str


def _candidates(dataset: Dataset, subdir: str) -> list[Path]:
    """The compilable .sol files of one subdirectory, in a stable order.

    Stable because `Dataset.files()` is sorted and `EXCLUDED` is subtracted by the same relative-path
    key, so the draw below sees the same list on every machine and every run.
    """
    excluded = EXCLUDED[dataset.name]
    folder = dataset.contracts / subdir
    return [
        path
        for path in dataset.files()
        if folder in path.parents and path.relative_to(dataset.contracts).as_posix() not in excluded
    ]


def smartbugs_cases() -> list[Case]:
    """Every compilable contract of the four sampled SmartBugs categories."""
    cases: list[Case] = []
    for category in mapping.SMARTBUGS_SAMPLED_CATEGORIES:
        swc = mapping.SMARTBUGS_CLASS[category]
        for path in _candidates(SMARTBUGS, category):
            cases.append(Case(SMARTBUGS.name, path, category, swc))
    return cases


def solidifi_cases() -> list[Case]:
    """`SOLIDIFI_PER_TYPE` contracts drawn per bug type with the experiment seed.

    One `random.Random(SEED)` is drawn from in a FIXED type order (`SOLIDIFI_SAMPLED_TYPES`), so the
    whole draw is reproducible from the single seed without hashing a string -- `Random` seeded with a
    non-integer would depend on `PYTHONHASHSEED` and stop being reproducible across processes.
    """
    rng = random.Random(SEED)
    cases: list[Case] = []
    for bug_type in mapping.SOLIDIFI_SAMPLED_TYPES:
        swc = mapping.SOLIDIFI_CLASS[bug_type]
        candidates = _candidates(SOLIDIFI, bug_type)
        for path in sorted(rng.sample(candidates, SOLIDIFI_PER_TYPE)):
            cases.append(Case(SOLIDIFI.name, path, bug_type, swc))
    return cases


def cases() -> list[Case]:
    """The whole 147-contract sample: all SmartBugs cases, then the SolidiFI draw."""
    return smartbugs_cases() + solidifi_cases()


#: Contracts drawn per SWC class for the timing / k subsample (chapter 2.3, "about 40 contracts").
SUBSAMPLE_PER_CLASS = 10


def subsample(per_class: int = SUBSAMPLE_PER_CLASS) -> list[Case]:
    """A balanced ~40-contract subsample for the costly real runs (M1-M4 timing, the k sweep).

    The head-to-head timing comparison and the k sweep re-execute the engine, so they run on a small
    subsample, not the whole 147 (chapter 2.3). `per_class` contracts are drawn for each of the four
    SWC classes with the experiment seed, so the draw is balanced for the macro-average and
    reproducible. Drawn from the full sample, so every contract is one `cases()` already verified.
    """
    rng = random.Random(SEED)
    pool = cases()
    chosen: list[Case] = []
    for swc in ("SC01", "SC06", "SC08", "SC09"):
        members = sorted((c for c in pool if c.swc == swc), key=lambda c: c.path.as_posix())
        chosen.extend(sorted(rng.sample(members, min(per_class, len(members))),
                             key=lambda c: c.path.as_posix()))
    return chosen


# ----------------------------------------------------------------------------- verification


def _compiled_paths(coverage_path: Path) -> set[str]:
    """The paths `coverage.py` managed to compile, as absolute POSIX strings."""
    data = json.loads(coverage_path.read_text(encoding="utf-8"))
    return {
        Path(report["path"]).as_posix()
        for report in data["contracts"]
        if report["solc_version"] and not report["error"]
    }


def verify(coverage_path: Path = Path("experiments/coverage.json")) -> list[str]:
    """Cross-check the sample against the measurement run; return a list of problems (empty if OK).

    Catches the drift this module is most exposed to: an `EXCLUDED` entry that no longer matches the
    measured failures, or an expected count that has moved because a dataset commit changed.
    """
    problems: list[str] = []
    sample = cases()
    compiled = _compiled_paths(coverage_path)

    for case in sample:
        if case.path.as_posix() not in compiled:
            problems.append(f"sampled but not compiled in coverage.json: {case.path}")

    smartbugs = [c for c in sample if c.dataset == SMARTBUGS.name]
    solidifi = [c for c in sample if c.dataset == SOLIDIFI.name]
    if len(smartbugs) != 112:
        problems.append(f"SmartBugs count {len(smartbugs)}, expected 112")
    if len(solidifi) != SOLIDIFI_PER_TYPE * len(mapping.SOLIDIFI_SAMPLED_TYPES):
        problems.append(f"SolidiFI count {len(solidifi)}, expected 35")
    return problems


def _summary(sample: list[Case]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in sample:
        key = f"{case.dataset}/{case.label}"
        counts[key] = counts.get(key, 0) + 1
    return counts


def main() -> int:
    sample = cases()
    for key, count in sorted(_summary(sample).items()):
        print(f"{key:<40}{count:>4}")
    print(f"{'total':<40}{len(sample):>4}")
    problems = verify()
    if problems:
        print("\nPROBLEMS:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("\nverified against coverage.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
