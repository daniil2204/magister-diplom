"""Evaluation metrics and the offline replay (chapter 2.3, formulas 2.20-2.24).

The module has three layers, each a set of pure functions so they can be tested without a full run:

* **ground truth** -- the SmartBugs / SolidiFI labels reduced to (SWC, function) units against the same
  pinned compilation the method uses (`experiments.units`), with labels outside any function dropped
  and counted;
* **scoring** -- confusion counts per class, Precision / Recall / F1 macro-averaged over the four SWC
  classes (the headline aggregation, because micro is dominated by SC09) and micro-averaged beside it,
  in strict (positive = CONFIRMED) and moderate (positive = CONFIRMED or UNKNOWN) modes, plus DeltaFP
  (2.23) and specificity on the fixed-version pairs;
* **replay** -- lambda and the weights change both the queue order and B_t (2.18), so a sweep cannot be
  read off one run. `replay` recomputes the queue, B_t and the carry from the reference run's static
  components and per-target times, exactly as `hsa.symexec.engine.analyze_targets` does online, and
  re-derives each verdict and its time from the start of the contract (for the simulated Recall(tau)).

The two statistical tests (2.3: McNemar for detection, Wilcoxon for time, alpha = 0.05) are implemented
in pure Python, so the package needs no scipy.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

from experiments import mapping
from experiments.datasets import SMARTBUGS, SOLIDIFI
from experiments.sample import Case
from experiments.units import function_at
from hsa.config import Config
from hsa.prep import Compilation

#: The classes the headline macro-average is taken over. SC10 is excluded: the sample holds only three
#: DC targets in two contracts, too few to estimate a class (chapter 2.3 reports it as case studies).
MACRO_CLASSES = ("SC01", "SC06", "SC08", "SC09")

#: Verdict aggregation strength, mirroring `hsa.model.VERDICT_STRENGTH` without importing Z3-backed code.
_STRENGTH = {"REFUTED": 0, "UNKNOWN": 1, "CONFIRMED": 2}


# ==================================================================== ground truth


@dataclass
class GroundTruth:
    """The labelled vulnerabilities of one contract as (SWC, function) units."""

    units: set[tuple[str, str]]
    dropped: int  # labels whose line fell outside every function


@lru_cache(maxsize=1)
def _smartbugs_index() -> dict[str, list[tuple[str, list[int]]]]:
    """vulnerabilities.json keyed by the path it stores (e.g. `dataset/reentrancy/x.sol`)."""
    payload = json.loads((SMARTBUGS.directory / "vulnerabilities.json").read_text(encoding="utf-8"))
    index: dict[str, list[tuple[str, list[int]]]] = {}
    for entry in payload:
        index[entry["path"].replace("\\", "/")] = [
            (vuln["category"], vuln["lines"]) for vuln in entry.get("vulnerabilities", [])
        ]
    return index


def _smartbugs_labels(path: Path) -> list[tuple[Optional[str], list[int]]]:
    key = path.resolve().relative_to(SMARTBUGS.directory.resolve()).as_posix()
    return [(mapping.smartbugs_swc(category), lines) for category, lines in _smartbugs_index().get(key, [])]


def _solidifi_labels(path: Path) -> list[tuple[Optional[str], list[int]]]:
    """SolidiFI: the bug type is the directory; each BugLog row gives the injected snippet's span.

    A row is the start line (`loc`) and line count (`length`) of a snippet SolidiFI injected. `loc`
    frequently lands on a declaration line of the snippet (e.g. a `mapping` or the opening brace), not
    on the vulnerable statement, so mapping the single `loc` line misses the function that actually
    holds the bug. The whole span `[loc, loc + length)` is the injected bug region (SolidiFI's own
    detection criterion), so every line of it is a label.
    """
    bug_type = path.parent.name
    swc = mapping.solidifi_swc(bug_type)
    buglog = path.parent / f"BugLog_{path.stem.split('_')[-1]}.csv"
    if not buglog.is_file():
        return []
    labels: list[tuple[Optional[str], list[int]]] = []
    with buglog.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            loc = int(row["loc"])
            length = int(row.get("length") or 1)
            labels.append((swc, list(range(loc, loc + max(length, 1)))))
    return labels


def ground_truth(case: Case, compilation: Compilation) -> GroundTruth:
    """The labelled units of one sampled contract.

    Labels of classes outside the method's five (SMARTBUGS `smartbugs_swc` -> None) are ignored;
    labels inside a mapped class but outside any function are dropped and counted (chapter 2.3).
    """
    path = Path(case.path)
    labels = _smartbugs_labels(path) if case.dataset == SMARTBUGS.name else _solidifi_labels(path)
    units: set[tuple[str, str]] = set()
    dropped = 0
    for swc, lines in labels:
        if swc is None:
            continue
        for line in lines:
            function = function_at(compilation, line)
            if function is None:
                dropped += 1
            else:
                units.add((swc, function))
    return GroundTruth(units=units, dropped=dropped)


# ==================================================================== predictions


def unit_verdicts(targets: Iterable[dict]) -> dict[tuple[str, str], str]:
    """Aggregate report targets into units (SWC, function), strongest verdict wins."""
    units: dict[tuple[str, str], str] = {}
    for target in targets:
        key = (target["swc"], target["function"])
        current = units.get(key)
        if current is None or _STRENGTH[target["verdict"]] > _STRENGTH[current]:
            units[key] = target["verdict"]
    return units


def positives(verdicts: dict[tuple[str, str], str], mode: str) -> set[tuple[str, str]]:
    """Positive units: strict counts only CONFIRMED, moderate counts CONFIRMED or UNKNOWN (2.3)."""
    allowed = {"CONFIRMED"} if mode == "strict" else {"CONFIRMED", "UNKNOWN"}
    return {unit for unit, verdict in verdicts.items() if verdict in allowed}


# ==================================================================== confusion & metrics


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def __add__(self, other: "Confusion") -> "Confusion":
        return Confusion(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn, self.tn + other.tn)

    @property
    def precision(self) -> Optional[float]:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> Optional[float]:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if not p or not r:
            return 0.0 if (self.tp + self.fp + self.fn) else None
        return 2 * p * r / (p + r)

    @property
    def specificity(self) -> Optional[float]:
        return self.tn / (self.tn + self.fp) if self.tn + self.fp else None


def confusion(predicted: set, truth: set, negatives: Optional[set] = None) -> Confusion:
    """Confusion of predicted positive units against the truth.

    The labelled sample has no true negatives (every contract is vulnerable), so `negatives` is None
    and TN stays 0. The fixed-version pairs supply negatives (the fixed-class units), so TN and the
    specificity are only meaningful there.
    """
    tp = len(predicted & truth)
    fp = len(predicted - truth)
    fn = len(truth - predicted)
    tn = len(negatives - predicted) if negatives is not None else 0
    return Confusion(tp=tp, fp=fp, fn=fn, tn=tn)


def per_class(predicted: set, truth: set, classes: Iterable[str] = MACRO_CLASSES) -> dict[str, Confusion]:
    """Confusion restricted to each class, where a unit's class is its SWC (unit = (swc, function))."""
    result = {}
    for swc in classes:
        p = {u for u in predicted if u[0] == swc}
        t = {u for u in truth if u[0] == swc}
        result[swc] = confusion(p, t)
    return result


def macro(by_class: dict[str, Confusion]) -> dict[str, Optional[float]]:
    """Macro-average: the mean over classes of each metric, ignoring classes that are undefined."""
    def mean(values: list[Optional[float]]) -> Optional[float]:
        present = [v for v in values if v is not None]
        return sum(present) / len(present) if present else None

    return {
        "precision": mean([c.precision for c in by_class.values()]),
        "recall": mean([c.recall for c in by_class.values()]),
        "f1": mean([c.f1 for c in by_class.values()]),
    }


def micro(by_class: dict[str, Confusion]) -> Confusion:
    total = Confusion()
    for conf in by_class.values():
        total = total + conf
    return total


def delta_fp(fp_m1: int, fp_m2: int) -> Optional[float]:
    """DeltaFP = 1 - FP_M1 / FP_M2 (2.23): the share of static false warnings the engine refuted."""
    return 1.0 - fp_m1 / fp_m2 if fp_m2 else None


# ==================================================================== offline replay


def _priority(static: dict, config: Config) -> float:
    risk = static["severity"] * (
        config.alpha * static["controllability"]
        + config.beta * static["exposure"]
        + config.gamma * static["value_factor"]
    )
    return risk * (1.0 + static["branch_count"]) ** (-config.lam)


def _node_key(target_id: str) -> tuple[str, str, str]:
    """(class, containing function, node) -- the identity the skip rule uses (2.18)."""
    vuln_class, _entry, function, node, _op = target_id.split("|")
    return (vuln_class, function, node)


def replay(
    statics: list[dict],
    reference: dict[str, dict],
    config: Config,
    static_elapsed: float = 0.0,
) -> list[dict]:
    """Re-derive the verdicts of one contract under `config` from the reference run (2.18).

    `statics` are the StaticTarget dicts; `reference` maps target_id to the reference target JSON
    (verdict, reason, time_to_verdict). The queue, B_t and the forward carry are rebuilt exactly as
    `analyze_targets` builds them online, and a target keeps its reference verdict only if its
    reference time fits inside the B_t it is granted; otherwise it is UNKNOWN `timeout`.
    """
    priorities = {s["target_id"]: _priority(s, config) for s in statics}
    total = sum(priorities.values())
    if total <= 0.0:
        allocation = {s["target_id"]: config.b_min for s in statics}
    else:
        allocation = {
            tid: max(config.b_min, config.budget * p / total) for tid, p in priorities.items()
        }

    if config.priority_ordered:
        queue = sorted(statics, key=lambda s: (-priorities[s["target_id"]], s["target_id"]))
    else:  # M4: seeded shuffle of a deterministic base
        import random

        queue = sorted(statics, key=lambda s: s["target_id"])
        random.Random(config.seed).shuffle(queue)

    results: list[dict] = []
    spent = 0.0
    bank = 0.0
    confirmed: set[tuple[str, str, str]] = set()
    for static in queue:
        tid = static["target_id"]
        base = allocation[tid]
        ref = reference[tid]
        swc, function = ref["swc"], ref["function"]

        remaining = config.budget - spent
        if remaining <= 0.0:
            results.append(_replayed(tid, swc, function, "UNKNOWN", "budget_exhausted",
                                     static_elapsed + spent))
            continue
        if _node_key(tid) in confirmed:
            bank += base
            results.append(_replayed(tid, swc, function, "UNKNOWN", "skipped_confirmed",
                                     static_elapsed + spent))
            continue

        granted = min(base + bank, remaining)
        ref_time = ref["time_to_verdict"]
        if ref.get("reason") == "timeout" or ref_time > granted:
            verdict, reason, elapsed = "UNKNOWN", "timeout", granted
        else:
            verdict, reason, elapsed = ref["verdict"], ref.get("reason"), ref_time
        spent += elapsed
        bank = max(0.0, bank + base - elapsed)
        if verdict == "CONFIRMED":
            confirmed.add(_node_key(tid))
        results.append(_replayed(tid, swc, function, verdict, reason, static_elapsed + spent))
    return results


def _replayed(tid, swc, function, verdict, reason, time_from_start) -> dict:
    return {
        "target_id": tid,
        "swc": swc,
        "function": function,
        "verdict": verdict,
        "reason": reason,
        "time_to_verdict": round(time_from_start, 3),
    }


# ==================================================================== Recall(tau)


def recall_at(replayed: list[dict], truth: set, tau: float) -> Optional[float]:
    """Recall(tau) (2.24): share of truth units CONFIRMED by a target no later than tau seconds."""
    if not truth:
        return None
    confirmed_in_time = {
        (t["swc"], t["function"])
        for t in replayed
        if t["verdict"] == "CONFIRMED" and t["time_to_verdict"] <= tau
    }
    return len(truth & confirmed_in_time) / len(truth)


# ==================================================================== statistics


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value on the discordant pair counts (b, c).

    The exact binomial test with p = 0.5, so no scipy and no chi-square approximation that would be
    unreliable at the small discordant counts the pairs produce.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def wilcoxon_signed_rank(xs: list[float], ys: list[float]) -> Optional[float]:
    """Two-sided Wilcoxon signed-rank p-value (normal approximation, tie-corrected).

    Compares paired times (e.g. method vs baseline). Returns None when every pair is tied, where the
    test is undefined. The normal approximation is adequate for the sample sizes of chapter 2.3.
    """
    diffs = [x - y for x, y in zip(xs, ys) if x != y]
    n = len(diffs)
    if n == 0:
        return None
    order = sorted(range(n), key=lambda i: abs(diffs[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(diffs[order[j + 1]]) == abs(diffs[order[i]]):
            j += 1
        average = (i + j) / 2 + 1  # ranks are 1-based
        for k in range(i, j + 1):
            ranks[order[k]] = average
        i = j + 1

    w_plus = sum(ranks[i] for i in range(n) if diffs[i] > 0)
    mean = n * (n + 1) / 4
    tie_term = 0.0
    counts: dict[float, int] = {}
    for r in sorted(abs(d) for d in diffs):
        counts[r] = counts.get(r, 0) + 1
    for t in counts.values():
        tie_term += t ** 3 - t
    variance = (n * (n + 1) * (2 * n + 1) - tie_term / 2) / 24
    if variance <= 0:
        return None
    z = (w_plus - mean) / math.sqrt(variance)
    return math.erfc(abs(z) / math.sqrt(2))
