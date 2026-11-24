"""Measurement run: which constructs outside table 2.1 the targets of the samples actually meet.

This is not an evaluation run. It issues no verdicts, calls no solver and needs no engine. For
every target of the static stage it walks N*_t -- the nodes from which the target is reachable,
the exact set the directed search will explore -- and labels the constructs the translator has no
rule for. Two things depend on the result:

* checking that struct flattening did what it was meant to. The first run said structs lay on
  51.4 % of the SmartBugs targets, which is what bought them one term per field; the share of
  targets that still abort on a struct has to be near zero now, and whatever is left is reported
  by its own label rather than as one "struct" number;
* chapter 3, which has to explain the UNKNOWN share. `unsupported_op` is the one UnknownReason
  that is a property of the sample rather than of the budget, so its size must be known.

The classification is static: a node is labelled by what it contains, not by executing it.
Executing linearly would mislabel perfectly supported code, because choosing branches is the
engine's job.

Usage:

    python -m experiments.coverage --out experiments/coverage.json [--jobs 8] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from slither.core.cfg.node import Node, NodeType
from slither.core.declarations import Function
from slither.core.solidity_types import ArrayType, ElementaryType, MappingType
from slither.slithir.operations import (
    Binary,
    BinaryType,
    Delete,
    HighLevelCall,
    Index,
    Operation,
    SolidityCall,
)
from slither.slithir.variables import Constant

from experiments.datasets import ALL, Dataset
from hsa.icfg import Expansion, inlined_callee
from hsa.model import Target
from hsa.prep import compile_contract
from hsa.static import detect
from hsa.static.base import Analysis
from hsa.symexec.state import UnsupportedConstruct, contains_mapping, flatten, struct_of


#: The labels, in reporting order. Every one of them aborts a path today.
#:
#: Plain structs are no longer here: they are flattened into one term per field. What is left of
#: them are the three cases the flattening does not reach, named separately so that chapter 3 can
#: report the residue by name rather than as one "struct" number.
LABELS = (
    "struct_abi",
    "struct_return",
    "struct_delete_mapping",
    "assembly",
    "bytes_index",
    "try_catch",
    "symbolic_power",
    "unsupported_type",
)

#: Measured but NOT gaps in table 2.1:
#:
#: * `internal_call` -- the engine inlines these up to depth d; the share of targets behind one is
#:   what makes the default d = 2 either enough or not;
#: * `struct` -- the presence of a struct at all. Before flattening this was a gap and was 51.4 %
#:   of the SmartBugs targets; keeping the count is how the re-measurement shows that the presence
#:   stayed while the abort went away;
#: * `recursive_call` -- a call in N*_t to a function already on its own ICFG chain. The ICFG does
#:   not unroll it, so the engine ends such a path UNKNOWN `recursion`; the share says how much of
#:   the sample that reason accounts for, which chapter 3 reports next to the other UNKNOWN reasons.
EXTRA_LABELS = ("struct", "internal_call", "recursive_call")


# ----------------------------------------------------------------------- classification


def _holds_struct(type_) -> bool:
    """Is there a struct in this type at all, however deep the containers go?

    `mapping(address => Account)` and `Outer[3][2]` count: the translator has to lay both of them
    out field by field, so both belong in the "struct" count.
    """
    if struct_of(type_) is not None:
        return True
    if isinstance(type_, MappingType):
        return _holds_struct(type_.type_to)
    if isinstance(type_, ArrayType):
        return _holds_struct(type_.type)
    return False


def _is_dynamic_bytes(type_) -> bool:
    return isinstance(type_, ElementaryType) and type_.name in ("bytes", "string")


def labels_of_node(node: Node) -> set[str]:
    """Everything in one node that table 2.1 has no rule for."""
    found: set[str] = set()
    if node.type in (NodeType.ASSEMBLY, NodeType.ENDASSEMBLY):
        found.add("assembly")
    if node.type in (NodeType.TRY, NodeType.CATCH):
        found.add("try_catch")

    for ir in node.irs:
        found |= labels_of_operation(ir)
    for variable in list(node.variables_read) + list(node.variables_written):
        found |= labels_of_type(getattr(variable, "type", None))
    return found


def labels_of_operation(ir: Operation) -> set[str]:
    found: set[str] = set()
    if isinstance(ir, Index) and _is_dynamic_bytes(getattr(ir.variable_left, "type", None)):
        found.add("bytes_index")
    if (
        isinstance(ir, Binary)
        and ir.type is BinaryType.POWER
        and not isinstance(ir.variable_right, Constant)
    ):
        found.add("symbolic_power")
    if inlined_callee(ir) is not None and not getattr(ir, "is_modifier_call", False):
        # An ordinary internal call or an internal/private library function (both inlined).
        found.add("internal_call")
    found |= _struct_residue(ir)
    return found


def _struct_residue(ir: Operation) -> set[str]:
    """The three places a struct still stops a path after flattening.

    Flattening lays a struct out field by field inside the state. It cannot help where the struct
    has to exist as one opaque value: packed into or out of `abi.*`, handed back by an external
    call whose code is unknown, or deleted whole while holding a mapping (there is no key set to
    iterate).
    """
    found: set[str] = set()
    if isinstance(ir, SolidityCall) and ir.function.name.startswith("abi."):
        operands = list(ir.arguments) + ([ir.lvalue] if ir.lvalue is not None else [])
        if any(_holds_struct(getattr(o, "type", None)) for o in operands):
            found.add("struct_abi")
    if isinstance(ir, HighLevelCall) and _holds_struct(getattr(ir.lvalue, "type", None)):
        found.add("struct_return")
    if isinstance(ir, Delete):
        type_ = getattr(ir.variable, "type", None)
        if struct_of(type_) is not None and contains_mapping(type_):
            found.add("struct_delete_mapping")
    return found


def labels_of_type(type_) -> set[str]:
    """`flatten` is the authority: it is how the translator lays a type out in Z3.

    A struct is counted but is no longer a gap -- it becomes one term per field. It only turns
    into `unsupported_type` when `flatten` itself refuses it, as it does for a recursive struct.
    """
    if type_ is None:
        return set()
    found = {"struct"} if _holds_struct(type_) else set()
    try:
        flatten(type_)
    except UnsupportedConstruct:
        found.add("unsupported_type")
    except Exception:  # Slither raises its own errors on a few unsized types
        found.add("unsupported_type")
    return found


# ----------------------------------------------------------------------------- scope


def scope_of(expansion: Expansion, target: Target) -> list[Node]:
    """N*_t: the nodes from which the target node is reachable in this expansion.

    Falls back to the whole expansion if the target node has no vertex, which would mean the
    static stage and the ICFG disagree -- recorded rather than silently dropped.
    """
    vertices = expansion.vertices_of(target.point.node)
    if not vertices:
        return [expansion.node(v) for v in expansion.vertices()]
    reachable: set = set()
    for vertex in vertices:
        reachable |= expansion.backward_reachable(vertex)
    return [expansion.node(v) for v in sorted(reachable, key=lambda v: (v.node_key, v.depth))]


def labels_of_target(analysis: Analysis, target: Target) -> set[str]:
    expansion = analysis.expansions[target.entry_point.canonical_name]
    found: set[str] = set()
    for node in scope_of(expansion, target):
        found |= labels_of_node(node)
    if _scope_has_recursion(expansion, target):
        found.add("recursive_call")
    return found


def _scope_has_recursion(expansion: Expansion, target: Target) -> bool:
    """True if some vertex of N*_t calls a function already on its own call chain (2.19).

    This mirrors the engine's recursion rule: a call whose callee is on the stack is not inlined, so
    the path ends UNKNOWN `recursion`. It is checked on vertices, not nodes, because recursion is a
    property of the call context, not of the source line.
    """
    vertices = expansion.vertices_of(target.point.node)
    reachable: set = set()
    for vertex in vertices:
        reachable |= expansion.backward_reachable(vertex)
    for vertex in reachable:
        on_stack = {frame.callee_key for frame in vertex.stack}
        for ir in expansion.node(vertex).irs:
            callee = inlined_callee(ir)
            if callee is not None and callee.canonical_name in on_stack:
                return True
    return False


# ------------------------------------------------------------------------- one contract


@dataclass
class ContractReport:
    dataset: str
    path: str
    solc_version: Optional[str] = None
    error: Optional[str] = None
    #: One entry per target: class, entry point, function, labels.
    targets: list[dict] = field(default_factory=list)
    #: Functions of the contract that contain assembly, whether or not they hold a target.
    assembly_functions: int = 0
    entry_points: int = 0

    def to_json(self) -> dict:
        return {
            "dataset": self.dataset,
            "path": self.path,
            "solc_version": self.solc_version,
            "error": self.error,
            "entry_points": self.entry_points,
            "assembly_functions": self.assembly_functions,
            "targets": self.targets,
        }


def measure(dataset_name: str, path: Path) -> ContractReport:
    """Compile one file, detect its targets and label the scope of each one.

    Never raises: a contract the pipeline cannot handle is a data point, not a crash.
    """
    report = ContractReport(dataset=dataset_name, path=str(path))
    try:
        compilation = compile_contract(path)
    except Exception as error:  # compilation, version selection, crytic-compile
        report.error = f"{type(error).__name__}: {error}".splitlines()[0][:300]
        return report

    report.solc_version = ".".join(str(p) for p in compilation.solc_version)
    try:
        for contract in compilation.slither.contracts:
            if contract.is_interface or contract.is_library:
                continue
            analysis = Analysis.build(compilation, contract)
            report.entry_points += len(analysis.expansions)
            report.assembly_functions += sum(
                1 for f in contract.functions if _contains_assembly(f)
            )
            for target in detect(compilation, contract):
                report.targets.append(
                    {
                        "contract": contract.name,
                        "class": target.vuln_class.name,
                        "entry_point": target.entry_point.name,
                        "function": target.function.name,
                        "line": target.point.node.source_mapping.lines[:1],
                        "labels": sorted(labels_of_target(analysis, target)),
                        "at_target": sorted(labels_of_node(target.point.node)),
                    }
                )
    except Exception:
        report.error = traceback.format_exc(limit=3).splitlines()[-1][:300]
    return report


def _contains_assembly(function: Function) -> bool:
    return any(n.type in (NodeType.ASSEMBLY, NodeType.ENDASSEMBLY) for n in function.nodes)


# ------------------------------------------------------------------------- the whole run


def _measure_one(argument: tuple[str, str]) -> dict:
    dataset_name, path = argument
    return measure(dataset_name, Path(path)).to_json()


def run(datasets: Iterable[Dataset], jobs: int, limit: Optional[int]) -> list[dict]:
    work: list[tuple[str, str]] = []
    for dataset in datasets:
        files = dataset.files()
        work.extend((dataset.name, str(p)) for p in (files[:limit] if limit else files))

    if jobs <= 1:
        return [_run_and_report(index, len(work), item) for index, item in enumerate(work)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        reports = []
        for index, report in enumerate(pool.map(_measure_one, work, chunksize=1)):
            _progress(index, len(work), report["path"])
            reports.append(report)
        return reports


def _run_and_report(index: int, total: int, item: tuple[str, str]) -> dict:
    _progress(index, total, item[1])
    return _measure_one(item)


def _progress(index: int, total: int, path: str) -> None:
    print(f"[{index + 1}/{total}] {Path(path).name}", file=sys.stderr)


# ------------------------------------------------------------------------------ summary


def _count(targets: list[dict]) -> dict[str, Counter]:
    """Two numbers per label, and they bracket the truth.

    `label` is the share of targets with the construct anywhere in N*_t -- an UPPER bound, since
    N*_t holds every branch that could reach the target and a single path takes only one of them.
    `label@target` is the share with it in the target operation itself -- a LOWER bound, because
    such a path always aborts. Nothing here can tell them apart without running the engine.
    """
    by_class: dict[str, Counter] = {}
    for target in targets:
        counter = by_class.setdefault(target["class"], Counter())
        counter["total"] += 1
        if any(label in LABELS for label in target["labels"]):
            counter["any"] += 1  # `internal_call` is deliberately not counted here
        for label in target["labels"]:
            counter[label] += 1
        for label in target["at_target"]:
            counter[label + "@target"] += 1
    return by_class


def summarise(reports: list[dict]) -> dict:
    targets = [t for r in reports for t in r["targets"]]
    by_class = _count(targets)
    overall = Counter()
    for counter in by_class.values():
        overall.update(counter)

    datasets = sorted({r["dataset"] for r in reports})
    return {
        "contracts": len(reports),
        "compiled": sum(1 for r in reports if r["solc_version"] and not r["error"]),
        "failed": sum(1 for r in reports if r["error"]),
        "failure_kinds": dict(
            Counter(r["error"].split(":")[0] for r in reports if r["error"]).most_common()
        ),
        "targets": len(targets),
        "overall": dict(overall),
        "by_class": {name: dict(counter) for name, counter in sorted(by_class.items())},
        "by_dataset": {name: _dataset_summary(reports, name) for name in datasets},
        "solc_versions": dict(
            Counter(r["solc_version"] for r in reports if r["solc_version"]).most_common()
        ),
    }


def _dataset_summary(reports: list[dict], name: str) -> dict:
    """Kept separate because the two samples are not comparable.

    SolidiFI injects many bugs into a few large contracts, so it contributes several times more
    targets than SmartBugs Curated. A pooled share is therefore a SolidiFI share.
    """
    chosen = [r for r in reports if r["dataset"] == name]
    targets = [t for r in chosen for t in r["targets"]]
    overall = Counter()
    for counter in _count(targets).values():
        overall.update(counter)
    return {
        "contracts": len(chosen),
        "compiled": sum(1 for r in chosen if r["solc_version"] and not r["error"]),
        "targets": len(targets),
        "overall": dict(overall),
    }


def print_table(summary: dict) -> None:
    print(
        f"\ncontracts {summary['contracts']}, compiled {summary['compiled']}, "
        f"failed {summary['failed']}, targets {summary['targets']}"
    )
    for name, part in summary["by_dataset"].items():
        print(
            f"  {name:<20}{part['compiled']:>4}/{part['contracts']:<5} compiled, "
            f"{part['targets']:>5} targets"
        )

    names = list(summary["by_dataset"])
    print(f"\n{'label':<18}{'all':>12}" + "".join(f"{n[:11]:>13}" for n in names))
    for label in ("any", *LABELS, *EXTRA_LABELS):
        cells = ""
        for name in names:
            part = summary["by_dataset"][name]
            cells += _cell(part["overall"].get(label, 0), part["targets"])
        print(f"{label:<18}" + _cell(summary["overall"].get(label, 0), summary["targets"]) + cells)

    print(f"\n{'class':<8}{'targets':>9}" + "".join(f"{l[:9]:>10}" for l in LABELS))
    for name, counter in summary["by_class"].items():
        row = counter.get("total", 0) or 1
        cells = "".join(f"{counter.get(label, 0) / row:>9.0%} " for label in LABELS)
        print(f"{name:<8}{counter.get('total', 0):>9}" + cells)


def _cell(count: int, total: int) -> str:
    return f"{count:>6}{count / (total or 1):>7.1%}"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("experiments/coverage.json"))
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--limit", type=int, default=None, help="first N files of each dataset")
    parser.add_argument("--dataset", action="append", help="dataset name, repeatable")
    arguments = parser.parse_args(argv)

    chosen = [d for d in ALL if not arguments.dataset or d.name in arguments.dataset]
    missing = [d.name for d in chosen if not d.contracts.is_dir()]
    if missing:
        parser.error(f"not cloned: {', '.join(missing)}")

    reports = run(chosen, arguments.jobs, arguments.limit)
    summary = summarise(reports)
    payload = {
        "datasets": [{"name": d.name, "commit": d.commit} for d in chosen],
        "summary": summary,
        "contracts": reports,
    }
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print_table(summary)
    print(f"\nwritten to {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
