"""Score the reference run: M1 (replayed), M2 (static-only) and the lambda / weight sensitivity.

This driver reads the artefacts `experiments/run.py` wrote for every sampled contract --
`<dataset>/<label>/<stem>.json` (the reference `ContractReport`) and `.static.pkl` (the
config-independent `StaticCache`) -- and turns them into the chapter 2.3 detection metrics WITHOUT
re-running the engine:

* **M1** is `metrics.replay(statics, reference, BASE)`: the queue, B_t and carry are rebuilt and each
  target keeps its reference verdict only if its reference time fits the B_t it is granted. The
  DETECTION of M1 is faithful this way; only the MEASURED timing of M1 needs a real run, which this
  driver does not do.
* **M2** is static-only: every detected target is a warning (UNKNOWN `static_only`), so in moderate
  every unit is a positive and strict is undefined (chapter 2.3).
* the **sensitivity sweeps** over lambda and the weights are likewise replays (they change only the
  queue order and B_t, never a single-target verdict), one `metrics.replay` per coefficient set.

The four head-to-head timing comparisons (M1 vs M3 vs M4) and the k sweep are NOT produced here: M3
changes which branches are explored and M4's hypothesis is MEASURED time, so each is a real timed run
(see `experiments/configs.py`).

Ground truth needs the label line mapped to its function, so each contract is recompiled once at the
solc version the reference run recorded (`metrics.ground_truth`).

Usage:

    python -m experiments.evaluate [--runs experiments/runs/reference]
"""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Optional

from experiments import configs, metrics
from experiments.metrics import Confusion, MACRO_CLASSES
from experiments.run import _destination
from experiments.sample import Case, cases
from hsa.config import Config
from hsa.prep import compile_contract

TAUS = (10, 30, 60, 120, 300)


def _target_id(target: dict) -> str:
    """Rebuild `run.target_id` from a report target (class|entry|function|node|op)."""
    return "|".join(
        (
            target["class"],
            target["entry_point"],
            target["function"],
            str(target["node_id"]),
            str(target["op_index"]),
        )
    )


def _load(runs: Path, case: Case) -> Optional[tuple[dict, dict]]:
    base = _destination(runs, case)
    report_path = base.with_suffix(".json")
    static_path = base.with_suffix(".static.pkl")
    if not report_path.is_file() or not static_path.is_file():
        return None
    report = json.loads(report_path.read_text(encoding="utf-8"))
    static = pickle.loads(static_path.read_bytes())
    return report, static


def _solc_version(report: dict) -> Optional[tuple[int, int, int]]:
    raw = report.get("solc_version")
    if not raw:
        return None
    parts = raw.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _sum_per_class(
    per_contract: list[dict[str, Confusion]]
) -> dict[str, Confusion]:
    totals = {swc: Confusion() for swc in MACRO_CLASSES}
    for by_class in per_contract:
        for swc in MACRO_CLASSES:
            totals[swc] = totals[swc] + by_class[swc]
    return totals


def _fmt(value: Optional[float]) -> str:
    return "  -  " if value is None else f"{value:.3f}"


def _print_table(title: str, by_class: dict[str, Confusion]) -> None:
    print(f"\n{title}")
    print(f"  {'class':6} {'P':>6} {'R':>6} {'F1':>6}   (tp/fp/fn)")
    for swc in MACRO_CLASSES:
        c = by_class[swc]
        print(
            f"  {swc:6} {_fmt(c.precision):>6} {_fmt(c.recall):>6} {_fmt(c.f1):>6}"
            f"   ({c.tp}/{c.fp}/{c.fn})"
        )
    m = metrics.macro(by_class)
    mi = metrics.micro(by_class)
    print(f"  {'MACRO':6} {_fmt(m['precision']):>6} {_fmt(m['recall']):>6} {_fmt(m['f1']):>6}")
    print(
        f"  {'MICRO':6} {_fmt(mi.precision):>6} {_fmt(mi.recall):>6} {_fmt(mi.f1):>6}"
        f"   ({mi.tp}/{mi.fp}/{mi.fn})"
    )


def evaluate(runs: Path) -> int:
    sample = cases()
    loaded: list[tuple[Case, dict, dict, set[tuple[str, str]]]] = []
    missing = 0
    errored = 0
    dropped = 0

    for case in sample:
        pair = _load(runs, case)
        if pair is None:
            missing += 1
            continue
        report, static = pair
        if report.get("error"):
            errored += 1
            continue
        compilation = compile_contract(case.path, _solc_version(report))
        gt = metrics.ground_truth(case, compilation)
        dropped += gt.dropped
        loaded.append((case, report, static, gt.units))

    print(
        f"loaded {len(loaded)} contracts  (missing {missing}, errored {errored}, "
        f"dropped labels {dropped})"
    )

    # ---- M1 (replayed) and M2 (static-only), strict and moderate ---------------
    m1_strict: list[dict[str, Confusion]] = []
    m1_moderate: list[dict[str, Confusion]] = []
    m2_moderate: list[dict[str, Confusion]] = []
    tau_hits = {tau: 0 for tau in TAUS}
    truth_total = 0

    for _case, report, static, truth in loaded:
        reference = {_target_id(t): t for t in report["targets"]}
        replayed = metrics.replay(
            static["targets"], reference, configs.BASE, static["static_elapsed"]
        )
        v1 = metrics.unit_verdicts(replayed)
        m1_strict.append(metrics.per_class(metrics.positives(v1, "strict"), truth))
        m1_moderate.append(metrics.per_class(metrics.positives(v1, "moderate"), truth))

        # M2: every detected target is a static warning -> positive in moderate.
        m2_units = {(t["swc"], t["function"]) for t in report["targets"]}
        m2_moderate.append(metrics.per_class(m2_units, truth))

        # Recall(tau), macro-class truth only, aggregated globally.
        macro_truth = {u for u in truth if u[0] in MACRO_CLASSES}
        truth_total += len(macro_truth)
        for tau in TAUS:
            confirmed_in_time = {
                (t["swc"], t["function"])
                for t in replayed
                if t["verdict"] == "CONFIRMED" and t["time_to_verdict"] <= tau
            }
            tau_hits[tau] += len(macro_truth & confirmed_in_time)

    _print_table("M1 (replayed) -- strict", _sum_per_class(m1_strict))
    _print_table("M1 (replayed) -- moderate", _sum_per_class(m1_moderate))
    _print_table("M2 (static-only) -- moderate", _sum_per_class(m2_moderate))

    fp_m1 = metrics.micro(_sum_per_class(m1_moderate)).fp
    fp_m2 = metrics.micro(_sum_per_class(m2_moderate)).fp
    print(f"\nDeltaFP (moderate, macro classes): {_fmt(metrics.delta_fp(fp_m1, fp_m2))}"
          f"   (FP_M1={fp_m1}, FP_M2={fp_m2})")

    print("\nRecall(tau) -- M1 replayed, macro-class truth, simulated")
    for tau in TAUS:
        r = tau_hits[tau] / truth_total if truth_total else None
        print(f"  tau={tau:>4}s : {_fmt(r)}   ({tau_hits[tau]}/{truth_total})")

    # ---- sensitivity: lambda and weight sweeps, replayed ----------------------
    print("\n=== sensitivity (replayed) ===")
    sweep = {**configs.lambda_sweep(), **configs.weight_sweep()}
    for name, config in sweep.items():
        _sensitivity_row(name, config, loaded)

    return 0


def _sensitivity_row(
    name: str,
    config: Config,
    loaded: list[tuple[Case, dict, dict, set[tuple[str, str]]]],
) -> None:
    strict: list[dict[str, Confusion]] = []
    moderate: list[dict[str, Confusion]] = []
    for _case, report, static, truth in loaded:
        reference = {_target_id(t): t for t in report["targets"]}
        replayed = metrics.replay(static["targets"], reference, config, static["static_elapsed"])
        v = metrics.unit_verdicts(replayed)
        strict.append(metrics.per_class(metrics.positives(v, "strict"), truth))
        moderate.append(metrics.per_class(metrics.positives(v, "moderate"), truth))
    ms = metrics.macro(_sum_per_class(strict))
    mm = metrics.macro(_sum_per_class(moderate))
    print(
        f"  {name:12} strict F1={_fmt(ms['f1'])} R={_fmt(ms['recall'])} | "
        f"moderate F1={_fmt(mm['f1'])} R={_fmt(mm['recall'])}"
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=Path, default=Path("experiments/runs/reference"))
    arguments = parser.parse_args(argv)
    return evaluate(arguments.runs)


if __name__ == "__main__":
    raise SystemExit(main())
