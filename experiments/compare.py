"""Score the timed subsample runs: the M1-M4 head-to-head, the k sweep and the Slither baseline.

Reads the artefacts `experiments/timed.py` wrote under `experiments/runs/<kind>/` for the 40-contract
subsample and turns them into the chapter 2.3 comparisons that the reference run cannot give:

* **detection per configuration** -- M1 (full), M2 (static-only), M3 (no pruning), M4 (random order),
  each as per-class / macro Precision, Recall, F1 in strict and moderate, against the same ground
  truth (`metrics.ground_truth`);
* **time** -- the measured per-contract `elapsed` of M1 vs M3 (hypothesis G3: directed search is
  faster) and M1 vs M4, with the Wilcoxon signed-rank p-value (2.3, alpha = 0.05);
* **the k sweep** -- F1 at k in {1, 2, 3}, re-executed (k changes the verdicts);
* **the Slither baseline** -- per-class detection and the exact McNemar p-value against M1.

Tolerant of a run still in progress: a configuration scores only the contracts whose report exists, and
prints how many that was, so it can be run against a partial `experiments/runs` while timed.py finishes.

Usage:

    python -m experiments.compare [--runs experiments/runs]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import median
from typing import Optional

from experiments import metrics
from experiments.metrics import Confusion, MACRO_CLASSES
from experiments.sample import Case, subsample
from hsa.prep import compile_contract

HSA_CONFIGS = ("M1", "M2", "M3", "M4")
K_CONFIGS = ("k1", "k2", "k3")


def _solc_version(report: dict) -> Optional[tuple[int, int, int]]:
    raw = report.get("solc_version")
    if not raw:
        return None
    a, b, c = raw.split(".")
    return (int(a), int(b), int(c))


def _report_path(runs: Path, kind: str, case: Case) -> Path:
    return runs / kind / case.dataset / case.label / f"{Path(case.path).stem}.json"


def _load_truth(sample: list[Case], runs: Path) -> dict[str, tuple[Case, set]]:
    """Ground truth per contract, compiled once at the M1 report's recorded solc version."""
    truth: dict[str, tuple[Case, set]] = {}
    for case in sample:
        m1 = _report_path(runs, "M1", case)
        if not m1.is_file():
            continue
        report = json.loads(m1.read_text(encoding="utf-8"))
        if report.get("error"):
            continue
        compilation = compile_contract(case.path, _solc_version(report))
        gt = metrics.ground_truth(case, compilation)
        truth[str(case.path)] = (case, gt.units)
    return truth


def _sum(per_contract: list[dict[str, Confusion]]) -> dict[str, Confusion]:
    totals = {swc: Confusion() for swc in MACRO_CLASSES}
    for by_class in per_contract:
        for swc in MACRO_CLASSES:
            totals[swc] = totals[swc] + by_class[swc]
    return totals


def _fmt(v: Optional[float]) -> str:
    return "  -  " if v is None else f"{v:.3f}"


def _score_config(
    name: str, runs: Path, truth: dict[str, tuple[Case, set]], mode: str
) -> tuple[dict[str, Confusion], int]:
    rows: list[dict[str, Confusion]] = []
    scored = 0
    for path, (case, units) in truth.items():
        report_path = _report_path(runs, name, case)
        if not report_path.is_file():
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report.get("error"):
            continue
        verdicts = metrics.unit_verdicts(report["targets"])
        rows.append(metrics.per_class(metrics.positives(verdicts, mode), units))
        scored += 1
    return _sum(rows), scored


def _print_config(name: str, runs: Path, truth: dict[str, tuple[Case, set]]) -> None:
    for mode in ("strict", "moderate"):
        if name == "M2" and mode == "strict":
            continue  # M2 is undefined in strict (every target is a warning)
        by_class, scored = _score_config(name, runs, truth, mode)
        m = metrics.macro(by_class)
        mi = metrics.micro(by_class)
        print(
            f"  {name:4} {mode:8} [{scored:2}] "
            f"macro P={_fmt(m['precision'])} R={_fmt(m['recall'])} F1={_fmt(m['f1'])} | "
            f"micro P={_fmt(mi.precision)} R={_fmt(mi.recall)} F1={_fmt(mi.f1)}"
        )


def _elapsed(runs: Path, name: str, truth: dict[str, tuple[Case, set]]) -> dict[str, float]:
    times: dict[str, float] = {}
    for path, (case, _units) in truth.items():
        rp = _report_path(runs, name, case)
        if not rp.is_file():
            continue
        report = json.loads(rp.read_text(encoding="utf-8"))
        if report.get("error") is None:
            times[path] = report["elapsed"]
    return times


def _time_comparison(runs: Path, a: str, b: str, truth: dict[str, tuple[Case, set]]) -> None:
    ta, tb = _elapsed(runs, a, truth), _elapsed(runs, b, truth)
    shared = sorted(set(ta) & set(tb))
    if not shared:
        print(f"  {a} vs {b}: no shared contracts yet")
        return
    xs = [ta[p] for p in shared]
    ys = [tb[p] for p in shared]
    p = metrics.wilcoxon_signed_rank(xs, ys)
    print(
        f"  {a} vs {b} [{len(shared)}]: median {a}={median(xs):.2f}s {b}={median(ys):.2f}s"
        f"  total {a}={sum(xs):.1f}s {b}={sum(ys):.1f}s  Wilcoxon p={_fmt(p)}"
    )


def _slither_units(runs: Path, case: Case) -> Optional[set[tuple[str, str]]]:
    rp = _report_path(runs, "slither", case)
    if not rp.is_file():
        return None
    report = json.loads(rp.read_text(encoding="utf-8"))
    return {
        (f["swc"], f["function"])
        for f in report.get("findings", [])
        if f["swc"] in MACRO_CLASSES and f["function"]
    }


def _baseline_vs_m1(runs: Path, truth: dict[str, tuple[Case, set]]) -> None:
    """Per-class detection of Slither vs M1 (strict), and the exact McNemar p-value on contracts."""
    slither_rows: list[dict[str, Confusion]] = []
    b = c = scored = 0  # McNemar discordant pairs over (unit) detections
    m1_total: dict[str, Confusion] = {swc: Confusion() for swc in MACRO_CLASSES}
    for path, (case, units) in truth.items():
        sl = _slither_units(runs, case)
        m1_path = _report_path(runs, "M1", case)
        if sl is None or not m1_path.is_file():
            continue
        report = json.loads(m1_path.read_text(encoding="utf-8"))
        if report.get("error"):
            continue
        scored += 1
        m1_pos = metrics.positives(metrics.unit_verdicts(report["targets"]), "strict")
        slither_rows.append(metrics.per_class(sl, units))
        for swc in MACRO_CLASSES:
            m1_total[swc] = m1_total[swc] + metrics.per_class(m1_pos, units)[swc]
        # McNemar on true-positive detection, per labelled unit.
        for unit in units:
            in_m1, in_sl = unit in m1_pos, unit in sl
            if in_m1 and not in_sl:
                b += 1
            elif in_sl and not in_m1:
                c += 1
    sl_total = _sum(slither_rows)
    print(f"  scored contracts: {scored}")
    print(f"  {'class':6} {'Slither R':>10} {'M1 R(strict)':>13}")
    for swc in MACRO_CLASSES:
        print(f"  {swc:6} {_fmt(sl_total[swc].recall):>10} {_fmt(m1_total[swc].recall):>13}")
    print(f"  McNemar on TP detection (M1-only={b}, Slither-only={c}): p={_fmt(metrics.mcnemar_exact(b, c))}")


def compare(runs: Path) -> int:
    sample = subsample()
    truth = _load_truth(sample, runs)
    print(f"ground truth loaded for {len(truth)}/{len(sample)} subsample contracts\n")

    print("=== detection per configuration ===")
    for name in HSA_CONFIGS:
        _print_config(name, runs, truth)

    print("\n=== k sweep (detection) ===")
    for name in K_CONFIGS:
        _print_config(name, runs, truth)

    print("\n=== time (measured, seconds) ===")
    _time_comparison(runs, "M1", "M3", truth)
    _time_comparison(runs, "M1", "M4", truth)

    print("\n=== Slither baseline vs M1 ===")
    _baseline_vs_m1(runs, truth)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=Path, default=Path("experiments/runs"))
    arguments = parser.parse_args(argv)
    return compare(arguments.runs)


if __name__ == "__main__":
    raise SystemExit(main())
