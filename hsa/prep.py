"""Compilation: pick a solc version for the source, build the Slither object.

The solc binary is passed to crytic-compile explicitly instead of going through
`solc-select use`. `solc-select use` mutates a global file shared by every process, which breaks
both determinism and the per-contract parallelism of the experiments.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import solc_select.solc_select as solc_select
from slither import Slither

#: Versions the method is written against. SmartBugs Curated and SolidiFI are mostly 0.4.x-0.6.x;
#: the reference fixtures are 0.4.24 and 0.8.20.
MIN_SUPPORTED = (0, 4, 11)
MAX_SUPPORTED = (0, 8, 30)

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_CONSTRAINT_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(\d+)\.(\d+)(?:\.(\d+))?")


class UnsupportedVersionError(Exception):
    """The source requires a solc version outside the supported window."""


@dataclass(frozen=True)
class Compilation:
    """A compiled contract file, ready for the static stage."""

    path: Path
    slither: Slither
    solc_version: tuple[int, int, int]
    #: Kept only to hold an ASCII workspace open for as long as the compilation is used.
    _workspace: Optional[tempfile.TemporaryDirectory] = field(default=None, repr=False)

    @property
    def checked_arithmetic(self) -> bool:
        """Solidity >= 0.8 inserts overflow checks outside `unchecked` blocks.

        Below 0.8 all arithmetic is unchecked, which is what makes the OV sink condition
        necessary on the old datasets.
        """
        return self.solc_version >= (0, 8, 0)


def parse_pragmas(source: str) -> list[tuple[Optional[str], tuple[int, int, int]]]:
    """Parse every `pragma solidity` constraint into (operator, version) pairs."""
    constraints: list[tuple[Optional[str], tuple[int, int, int]]] = []
    for raw in _PRAGMA_RE.findall(source):
        for op, major, minor, patch in _CONSTRAINT_RE.findall(raw):
            version = (int(major), int(minor), int(patch) if patch else 0)
            constraints.append((op or None, version))
    return constraints


def _satisfies(candidate: tuple[int, int, int], op: Optional[str], bound: tuple[int, int, int]) -> bool:
    if op == "^":
        if bound[0] == 0:
            return candidate >= bound and candidate[:2] == bound[:2]
        return candidate >= bound and candidate[0] == bound[0]
    if op == "~":
        return candidate >= bound and candidate[:2] == bound[:2]
    if op == ">=":
        return candidate >= bound
    if op == "<=":
        return candidate <= bound
    if op == ">":
        return candidate > bound
    if op == "<":
        return candidate < bound
    return candidate == bound


#: Operators that cap the version from above on their own. `>` and `>=` do not, and a pragma
#: built only from those needs `_implied_ceiling`.
_BOUNDED_ABOVE = (None, "=", "<", "<=", "^", "~")


def _implied_ceiling(
    constraints: list[tuple[Optional[str], tuple[int, int, int]]]
) -> Optional[tuple[int, int]]:
    """The minor version a pragma without an upper bound is nevertheless written against.

    `pragma solidity >=0.5.11;` admits 0.8.30 literally, but the file was written in the 0.5 era,
    and Solidity breaks syntax between minor versions: `function () external payable` is an error
    from 0.6 on. Taking the highest compatible version there costs 56 of the 350 SolidiFI
    contracts, all of them for that reason alone.

    So a pragma whose constraints are all lower bounds is capped at the minor version of the
    highest of them. With no constraints at all there is nothing to derive a ceiling from.
    """
    if not constraints or any(op in _BOUNDED_ABOVE for op, _ in constraints):
        return None
    return max(bound for _, bound in constraints)[:2]


def select_version(source: str) -> tuple[int, int, int]:
    """Choose the highest released solc version satisfying every pragma in the file.

    "Highest" is capped at the minor version of the pragma when the pragma has no upper bound
    of its own (see `_implied_ceiling`).

    Deterministic: depends only on the source text and the published version list.
    """
    constraints = parse_pragmas(source)
    ceiling = _implied_ceiling(constraints)
    available = sorted(
        {v for v in (_parse(x) for x in solc_select.get_available_versions()) if v is not None}
    )
    candidates = [
        v
        for v in available
        if MIN_SUPPORTED <= v <= MAX_SUPPORTED
        and (ceiling is None or v[:2] == ceiling)
        and all(_satisfies(v, op, bound) for op, bound in constraints)
    ]
    if not candidates:
        raise UnsupportedVersionError(
            f"no supported solc for pragmas {constraints!r} "
            f"(window {MIN_SUPPORTED}-{MAX_SUPPORTED})"
        )
    return candidates[-1]


def _parse(text: str) -> Optional[tuple[int, int, int]]:
    match = _VERSION_RE.fullmatch(text.strip())
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _format(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def solc_binary(version: tuple[int, int, int]) -> Path:
    """Return the path of the solc binary, installing it on first use."""
    text = _format(version)
    if text not in solc_select.installed_versions():
        solc_select.install_artifacts([text], silent=True)
    path = Path(solc_select.ARTIFACTS_DIR) / f"solc-{text}" / f"solc-{text}"
    if not path.exists():  # Windows artifacts sometimes keep the .exe suffix
        alternative = path.with_suffix(".exe")
        if alternative.exists():
            return alternative
        raise UnsupportedVersionError(f"solc {text} is not installed at {path}")
    return path


def _ascii_workspace(
    source_path: Path,
) -> tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    """Give solc an ASCII path to work with.

    solc 0.4.x on Windows re-encodes the file name it echoes back, so a project directory with
    non-ASCII characters makes crytic-compile fail to match the compilation output to the input.
    Copying the source into a temporary ASCII directory avoids this; line numbers are unaffected.
    """
    if str(source_path).isascii():
        return (source_path, None)
    workspace = tempfile.TemporaryDirectory(prefix="hsa_")
    copy = Path(workspace.name) / source_path.name
    shutil.copyfile(source_path, copy)
    return (copy, workspace)


def compile_contract(path: str | Path, version: Optional[tuple[int, int, int]] = None) -> Compilation:
    """Compile one .sol file and return the Slither object together with the version used."""
    source_path = Path(path)
    source = source_path.read_text(encoding="utf-8")
    chosen = version or select_version(source)
    target, workspace = _ascii_workspace(source_path)
    slither = Slither(str(target), solc=str(solc_binary(chosen)))
    return Compilation(
        path=source_path, slither=slither, solc_version=chosen, _workspace=workspace
    )
