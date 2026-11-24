"""Mapping a source line to the function that contains it.

Chapter 2.3 evaluates on units (SWC class, function), and three inputs arrive as line numbers rather
than functions: the SmartBugs / SolidiFI ground-truth labels, the Slither findings and the Mythril
findings. All three are resolved against the SAME pinned compilation as the method's own run, so a
baseline finding and a method target that touch one line land on one function name and are comparable.

The tightest enclosing declaration wins: a modifier body sits inside a function's line span, and a
target in a modifier is its own unit (chapter 2.3), so the narrower span is the right answer.
"""

from __future__ import annotations

from typing import Optional

from slither.core.declarations import Function

from hsa.prep import Compilation


def declarations(compilation: Compilation) -> list[Function]:
    """Every function and modifier of every contract in the file, with a source span.

    Not restricted to the analysed (derived, non-library) contracts: a baseline tool may report in a
    library or a base contract, and such a finding still has to map to a function name.
    """
    seen: dict[str, Function] = {}
    for contract in compilation.slither.contracts:
        for function in list(contract.functions) + list(contract.modifiers):
            if function.source_mapping and function.source_mapping.lines:
                seen.setdefault(function.canonical_name, function)
    return list(seen.values())


def function_at(compilation: Compilation, line: int) -> Optional[str]:
    """The canonical name of the tightest function/modifier whose span contains `line`.

    `None` when the line is in no function -- a state variable declaration, a pragma, a contract
    header. Chapter 2.3 excludes such labels from the units and counts how many were dropped.
    """
    best: Optional[Function] = None
    best_span = None
    for function in declarations(compilation):
        lines = function.source_mapping.lines
        if line < lines[0] or line > lines[-1]:
            continue
        span = lines[-1] - lines[0]
        if best is None or span < best_span:
            best, best_span = function, span
    return best.canonical_name if best is not None else None
