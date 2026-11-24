"""The baseline tools, Slither and Mythril, reduced to the same (SWC, function) units as the method.

Chapter 2.3 compares the method against both under one per-contract timeout. To be a fair comparison
the baselines see the SAME compilation the method does: the pinned solc of `prep.compile_contract` and
the same line-to-function resolution (`experiments.units`). A Slither finding, a Mythril finding and a
method target that touch one line therefore land on one function name.

* **Slither** is run in process on the already-built Slither object, with only the detectors that map
  to one of the method's classes (`experiments.mapping.SLITHER_CLASS`) registered. It is static and
  fast, so the timeout is recorded but not enforced mid-run; this is noted as a limitation.
* **Mythril** is a separate symbolic executor with its own solc handling, so it is run as a subprocess
  (`myth analyze ... -o json`) under a hard `--execution-timeout`, and its JSON is parsed back to
  findings. The parser is pure so it can be tested without the tool installed.

Only detectors / SWC ids that map to the five method classes are kept; `arbitrary-send-eth` and
SWC-105 are deliberately not mapped (an unprotected ether send is not in the method's Priv set), so
they never become baseline positives.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from slither.detectors import all_detectors

from experiments import mapping
from experiments.units import function_at
from hsa.prep import Compilation, compile_contract, solc_binary


class BaselineUnavailable(Exception):
    """The baseline tool is not installed, so it cannot be run (but its parser still can)."""


def _slither_detectors() -> dict[str, type]:
    """Resolve the mapped detector arguments to classes on the installed Slither.

    Resolved by `ARGUMENT` rather than by class name so a rename in a future Slither is discovered
    here instead of silently dropping a detector.
    """
    wanted = set(mapping.SLITHER_CLASS)
    resolved: dict[str, type] = {}
    for name in dir(all_detectors):
        cls = getattr(all_detectors, name)
        argument = getattr(cls, "ARGUMENT", None)
        if isinstance(argument, str) and argument in wanted:
            resolved[argument] = cls
    return resolved


@dataclass(frozen=True)
class Finding:
    """One baseline warning, reduced to the unit the evaluation compares on."""

    tool: str
    swc: str
    function: Optional[str]  # None if the warning is outside any function
    line: Optional[int]
    detector: str  # the raw Slither check or Mythril SWC id, kept for the manual review


@dataclass
class BaselineReport:
    tool: str
    path: str
    solc_version: Optional[str] = None
    elapsed: float = 0.0
    timed_out: bool = False
    error: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)

    def units(self) -> set[tuple[str, str]]:
        """(SWC, function) units: a unit is positive if the tool warns of that class in it."""
        return {(f.swc, f.function) for f in self.findings if f.function is not None}

    def to_json(self) -> dict:
        return {
            "tool": self.tool,
            "contract": self.path,
            "solc_version": self.solc_version,
            "elapsed": round(self.elapsed, 3),
            "timed_out": self.timed_out,
            "error": self.error,
            "findings": [
                {
                    "swc": f.swc,
                    "function": f.function,
                    "line": f.line,
                    "detector": f.detector,
                }
                for f in self.findings
            ],
            "units": [{"swc": swc, "function": function} for swc, function in sorted(self.units())],
        }


# ----------------------------------------------------------------------------------- Slither


def _result_functions(compilation: Compilation, result: dict) -> set[Optional[str]]:
    """The functions a Slither result points at, by resolving its elements' lines.

    Prefers the `function` elements; falls back to every element's first line so a result that only
    marks nodes still maps somewhere.
    """
    elements = result.get("elements", [])
    functions = [e for e in elements if e.get("type") == "function"]
    chosen = functions or elements
    lines: set[int] = set()
    for element in chosen:
        element_lines = (element.get("source_mapping") or {}).get("lines") or []
        if element_lines:
            lines.add(element_lines[0])
    return {function_at(compilation, line) for line in lines}


def slither_report(compilation: Compilation, timeout: float) -> BaselineReport:
    """Run the mapped Slither detectors on an already-built compilation."""
    report = BaselineReport(
        tool="slither",
        path=str(compilation.path),
        solc_version=".".join(str(p) for p in compilation.solc_version),
    )
    started = time.perf_counter()
    try:
        for detector in _slither_detectors().values():
            compilation.slither.register_detector(detector)
        groups = compilation.slither.run_detectors()
    except Exception as error:  # noqa: BLE001 - a baseline failure is a data point
        report.error = f"{type(error).__name__}: {error}".splitlines()[0][:300]
        report.elapsed = time.perf_counter() - started
        return report

    report.elapsed = time.perf_counter() - started
    report.timed_out = report.elapsed > timeout
    for group in groups:
        for result in group:
            check = result.get("check")
            swc = mapping.slither_swc(check)
            if swc is None:
                continue
            for function in _result_functions(compilation, result):
                report.findings.append(Finding("slither", swc, function, None, check))
    return report


def run_slither(path: str | Path, timeout: float) -> BaselineReport:
    """Compile with the pinned solc and run the Slither baseline. Never raises."""
    source = Path(path)
    try:
        compilation = compile_contract(source)
    except Exception as error:  # noqa: BLE001
        return BaselineReport(
            tool="slither", path=str(source), error=f"{type(error).__name__}: {error}"
        )
    return slither_report(compilation, timeout)


# ----------------------------------------------------------------------------------- Mythril


def _normalise_swc(raw) -> Optional[str]:
    """Mythril reports `swc-id` as either `107` or `SWC-107`; normalise to `SWC-107`."""
    if raw is None:
        return None
    text = str(raw)
    return text if text.startswith("SWC-") else f"SWC-{text}"


def parse_mythril(payload: dict, compilation: Compilation) -> list[Finding]:
    """Parse one `myth analyze -o json` object into findings.

    Pure so it is testable without Mythril installed. `lineno` is resolved against the method's own
    compilation, so a Mythril line and a method line map to the same function.
    """
    findings: list[Finding] = []
    for issue in payload.get("issues", []):
        swc = mapping.mythril_swc(_normalise_swc(issue.get("swc-id")))
        if swc is None:  # outside the five classes, e.g. SWC-105
            continue
        line = issue.get("lineno")
        function = function_at(compilation, line) if isinstance(line, int) else None
        findings.append(Finding("mythril", swc, function, line, _normalise_swc(issue.get("swc-id"))))
    return findings


def run_mythril(path: str | Path, timeout: float) -> BaselineReport:
    """Run Mythril as a subprocess under a hard timeout and parse its JSON. Never raises.

    Compiles the file with the method's pinned solc first, both to resolve lines to functions and to
    hand Mythril the same solc binary (`--solv` by version), so the comparison is on one compilation.
    """
    source = Path(path)
    report = BaselineReport(tool="mythril", path=str(source))
    try:
        compilation = compile_contract(source)
    except Exception as error:  # noqa: BLE001
        report.error = f"{type(error).__name__}: {error}"
        return report
    report.solc_version = ".".join(str(p) for p in compilation.solc_version)

    binary = solc_binary(compilation.solc_version)
    command = [
        "myth",
        "analyze",
        str(source),
        "-o",
        "json",
        "--execution-timeout",
        str(int(timeout)),
        "--solv",
        ".".join(str(p) for p in compilation.solc_version),
    ]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # grace over Mythril's own --execution-timeout
            env={"SOLC_BINARY": str(binary)},
        )
    except FileNotFoundError as error:
        raise BaselineUnavailable("myth is not installed") from error
    except subprocess.TimeoutExpired:
        report.elapsed = time.perf_counter() - started
        report.timed_out = True
        return report
    report.elapsed = time.perf_counter() - started

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report.error = (completed.stderr or completed.stdout or "no output").splitlines()[-1][:300]
        return report
    report.findings = parse_mythril(payload, compilation)
    return report


# ------------------------------------------------------------------------------------ driver


def _write(report: BaselineReport, out: Path, case) -> dict:
    # Nest by `case.label` (the dataset subdirectory) so SolidiFI stems that repeat across bug-type
    # folders do not overwrite each other -- same reason as `experiments.run._destination`.
    destination = out / report.tool / case.dataset / case.label / (Path(case.path).stem + ".json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report.to_json(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return {"tool": report.tool, "path": report.path, "units": len(report.units()),
            "error": report.error, "timed_out": report.timed_out}


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    import sys

    from experiments.sample import cases

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("experiments/runs/baselines"))
    parser.add_argument("--timeout", type=float, default=300.0, help="seconds per contract")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--tool", choices=["slither", "mythril"], action="append",
        help="which baseline to run; default is both",
    )
    arguments = parser.parse_args(argv)
    tools = arguments.tool or ["slither", "mythril"]

    sample = cases()
    if arguments.limit:
        sample = sample[: arguments.limit]

    mythril_available = True
    for index, case in enumerate(sample):
        if "slither" in tools:
            summary = _write(run_slither(case.path, arguments.timeout), arguments.out, case)
            print(f"[{index + 1}/{len(sample)}] slither {Path(case.path).name}: "
                  f"{summary['units']} units", file=sys.stderr)
        if "mythril" in tools and mythril_available:
            try:
                summary = _write(run_mythril(case.path, arguments.timeout), arguments.out, case)
                print(f"[{index + 1}/{len(sample)}] mythril {Path(case.path).name}: "
                      f"{summary['units']} units", file=sys.stderr)
            except BaselineUnavailable as error:
                print(f"mythril unavailable, skipping: {error}", file=sys.stderr)
                mythril_available = False
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
