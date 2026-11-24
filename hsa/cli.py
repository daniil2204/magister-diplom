"""Command line entry point: `hsa analyze <file.sol> --config M1 --budget 300 --out result.json`.

`analyze` is also the function `experiments/run.py` calls, so the CLI adds argument parsing and
nothing else. It builds the per-contract `Analysis` once and hands every target to the engine
orchestration (`analyze_targets`), so detection and symbolic execution share the same interprocedural
expansions rather than rebuilding them.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Optional, Sequence

from slither.core.declarations import Contract

from hsa.config import Config, Mode
from hsa.prep import compile_contract
from hsa.report import ContractReport, write_json
from hsa.static import DETECTORS
from hsa.static.base import Analysis
from hsa.symexec.engine import analyze_targets


def analysed_contracts(slither) -> list[Contract]:
    """Contracts worth analysing: the most derived ones, with their inherited code.

    Libraries and interfaces are skipped: a library has no storage of its own and an interface
    has no bodies, so neither can carry a target of any class.
    """
    return [
        contract
        for contract in slither.contracts_derived
        if not contract.is_library and not contract.is_interface
    ]


def analyze(
    path: str | Path,
    config: Optional[Config] = None,
    version: Optional[tuple[int, int, int]] = None,
) -> ContractReport:
    """Analyse one .sol file and return its report.

    Never raises: a contract that cannot be compiled becomes a report with `error` set and no
    targets, so a dataset run is not stopped by one bad file.
    """
    config = config or Config()
    source = Path(path)
    started = time.perf_counter()
    try:
        compilation = compile_contract(source, version)
    except Exception as error:  # noqa: BLE001 - the run must survive any compiler failure
        return ContractReport(
            path=source,
            config=config,
            elapsed=time.perf_counter() - started,
            error=f"{type(error).__name__}: {error}",
        )

    # Build the Analysis once per contract so detection and symbolic execution share the ICFG.
    pairs = [
        (analysis, target)
        for contract in analysed_contracts(compilation.slither)
        for analysis in [Analysis.build(compilation, contract)]
        for detector in DETECTORS
        for target in detector.detect(analysis)
    ]
    static_elapsed = time.perf_counter() - started

    results = analyze_targets(pairs, config, static_elapsed=static_elapsed)
    return ContractReport(
        path=source,
        config=config,
        solc_version=compilation.solc_version,
        results=results,
        elapsed=time.perf_counter() - started,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hsa", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyse one Solidity file")
    run.add_argument("source", type=Path, help="path to the .sol file")
    run.add_argument(
        "--config",
        default=Mode.M1.value,
        choices=[mode.value for mode in Mode],
        help="experiment configuration (default: M1)",
    )
    run.add_argument("--budget", type=float, default=Config.budget, help="seconds per contract")
    run.add_argument("--lam", type=float, default=Config.lam, help="lambda of formula (2.17)")
    run.add_argument("--seed", type=int, default=Config.seed, help="seed for M4")
    run.add_argument("--out", type=Path, default=None, help="write the JSON report here")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config(
        mode=Mode(args.config), budget=args.budget, lam=args.lam, seed=args.seed
    )
    report = analyze(args.source, config)
    print(report.text())
    if args.out is not None:
        write_json(report, args.out)
    return 1 if report.error else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
