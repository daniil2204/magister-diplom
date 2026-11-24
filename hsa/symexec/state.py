"""Symbolic state Sigma = <rho, mu, PC, tau> over Z3 (2.4).

`hsa.model.SymState` is the plain container shared with the rest of the package. Everything that
needs Z3 lives here, so the static stage never pulls in the solver.

Split of the state, following (2.4):

* rho -- local variables, parameters and the environment X_env; also the *locations* denoted by
  SlithIR reference variables, which is what a reference is in Solidity;
* mu  -- storage, one term per state variable. X_sto is free: every state variable starts as a
  fresh symbol, because the storage at the start of the transaction is arbitrary;
* PC  -- the path condition;
* tau -- the event trace the predicates of chapter 2 are written over.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import z3
from slither.core.declarations import Contract, Enum as SolidityEnum, Function, Structure
from slither.core.solidity_types import (
    ArrayType,
    ElementaryType,
    MappingType,
    Type,
    UserDefinedType,
)
from slither.core.variables.state_variable import StateVariable

from hsa.model import SymState

ADDRESS_BITS = 160
WORD_BITS = 256

#: Upper bound on `msg.value`, in bits: an attacker cannot send more ether than exists.
#:
#: Without it the solver may send 2^256 - 1 wei, and then almost every pre-0.8 `payable` function
#: with `balances[x] += msg.value` is a confirmed overflow -- a false positive produced entirely by
#: the model. The total supply of ether is about 1.2e26 wei, below 2^87; 2^128 keeps a very wide
#: margin while still cutting off the unreachable region.
VALUE_BITS = 128

#: Opaque sort for dynamically sized byte strings (`bytes`, `string`, `msg.data`). The method
#: never indexes into them -- they are compared, hashed or forwarded -- so an uninterpreted sort
#: says exactly as much as is modelled and no more.
BYTES = z3.DeclareSort("Bytes")

#: X_env of formula (2.3), in the spelling Slither uses.
SENDER = "msg.sender"
ORIGIN = "tx.origin"
VALUE = "msg.value"
DATA = "msg.data"


class UnsupportedConstruct(Exception):
    """Something table 2.1 does not model, for instance `assembly` or a struct.

    The engine catches it, abandons the path and reports UNKNOWN with `unsupported_op`. The
    analysis never fails with an exception.
    """


# ------------------------------------------------------------------------------- sorts


def is_signed(type_: Optional[Type]) -> bool:
    """True for `intN`. Needed because Z3's `<` on bitvectors is the SIGNED comparison."""
    return isinstance(type_, ElementaryType) and type_.name.startswith("int")


def sort_of(type_: Optional[Type]) -> z3.SortRef:
    """The Z3 sort of a Solidity type (table 2.1).

    A struct has no sort of its own: it is taken apart into one term per field by `flatten`.
    """
    if isinstance(type_, ElementaryType):
        return _elementary_sort(type_)
    if isinstance(type_, MappingType):
        return z3.ArraySort(sort_of(type_.type_from), sort_of(type_.type_to))
    if isinstance(type_, ArrayType):
        return z3.ArraySort(z3.BitVecSort(WORD_BITS), sort_of(type_.type))
    if isinstance(type_, UserDefinedType):
        target = type_.type
        if isinstance(target, Contract):
            return z3.BitVecSort(ADDRESS_BITS)  # a contract reference is an address
        if isinstance(target, SolidityEnum):
            return z3.BitVecSort(WORD_BITS)
    raise UnsupportedConstruct(f"no Z3 sort for type {type_!r}")


def _elementary_sort(type_: ElementaryType) -> z3.SortRef:
    name = type_.name
    if name == "bool":
        return z3.BoolSort()  # ElementaryType('bool').size is 8, which is not what we want
    if name in ("address", "address payable"):
        return z3.BitVecSort(ADDRESS_BITS)
    if name in ("bytes", "string"):
        return BYTES
    try:
        return z3.BitVecSort(type_.size)
    except Exception as error:  # dynamically sized or otherwise unsized
        raise UnsupportedConstruct(f"no Z3 sort for elementary type {name}") from error


def zero(sort: z3.SortRef) -> z3.ExprRef:
    """The default value Solidity gives an uninitialised variable."""
    if sort == z3.BoolSort():
        return z3.BoolVal(False)
    if isinstance(sort, z3.BitVecSortRef):
        return z3.BitVecVal(0, sort.size())
    if isinstance(sort, z3.ArraySortRef):
        return z3.K(sort.domain(), zero(sort.range()))
    raise UnsupportedConstruct(f"no zero value for sort {sort}")


# ------------------------------------------------------------------------------ structs


def struct_of(type_: Optional[Type]) -> Optional[Structure]:
    """The Structure a type denotes, or None if it is not a struct."""
    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
        return type_.type
    return None


def contains_mapping(type_: Optional[Type]) -> bool:
    """Does this type hold a mapping anywhere inside it?

    Only asked about structs, and only by `delete`: Solidity's `delete` skips the mappings in a
    struct instead of clearing them, and the method does not model that (it is in the list of
    constructs left as `unsupported_op`).
    """
    if isinstance(type_, MappingType):
        return True
    if isinstance(type_, ArrayType):
        return contains_mapping(type_.type)
    structure = struct_of(type_)
    return structure is not None and any(
        contains_mapping(element.type) for element in structure.elems_ordered
    )


def flatten(type_: Optional[Type], _seen: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], z3.SortRef]]:
    """Take a type apart into one (field path, sort) leaf per scalar component.

    This is struct flattening (the decision recorded after the measurement run): a struct never
    becomes a Z3 value, each of its fields becomes a term of its own. The containers around the
    struct stay where they are, so

        mapping(address => Account)  with Account {uint balance; uint nonce;}

    gives `Array(address, uint256)` twice, once named `.balance` and once `.nonce`. Writing one
    field therefore cannot touch the other, which is the property `Struct_bank` checks.

    Mappings and arrays wrap every leaf below them, so the key order of a location is preserved:
    `deeps[i].m[j].a` reads `Select(Select(deeps.m.a, i), j)`.
    """
    structure = struct_of(type_)
    if structure is not None:
        if structure.canonical_name in _seen:
            raise UnsupportedConstruct(f"recursive struct {structure.canonical_name}")
        leaves: list[tuple[tuple[str, ...], z3.SortRef]] = []
        for element in structure.elems_ordered:
            for path, sort in flatten(element.type, _seen + (structure.canonical_name,)):
                leaves.append(((element.name,) + path, sort))
        return leaves
    if isinstance(type_, MappingType) and struct_of(type_.type_to) is not None:
        key = sort_of(type_.type_from)
        return [(path, z3.ArraySort(key, sort)) for path, sort in flatten(type_.type_to, _seen)]
    if isinstance(type_, ArrayType) and struct_of(type_.type) is not None:
        key = z3.BitVecSort(WORD_BITS)
        return [(path, z3.ArraySort(key, sort)) for path, sort in flatten(type_.type, _seen)]
    return [((), sort_of(type_))]


# ---------------------------------------------------------------------------- locations


@dataclass(frozen=True)
class Field:
    """A struct field inside a location path. See `Location` for why it is not a key."""

    name: str


@dataclass(frozen=True)
class Location:
    """What a SlithIR reference variable denotes: a place, not a value.

    `REF_0 -> balances[msg.sender]` is a location; the later `REF_0 = REF_0 - v` writes through
    it. `path` is a chain so that `allowed[owner][spender]` is one location rather than a special
    case.

    A step of the chain is either a key (a Z3 term) or a `Field`. The two are resolved
    differently, and that is exactly struct flattening: the fields pick the *term*, the keys index
    into it. `accounts[a].balance` is the term named `C.accounts.balance` selected at `a`.
    """

    base: str  # name of the state variable, or of the local holding a memory record
    in_storage: bool
    path: tuple = ()
    variable: Optional[StateVariable] = None  # the state variable, for the trace events

    def index(self, key: z3.ExprRef) -> "Location":
        return Location(self.base, self.in_storage, self.path + (key,), self.variable)

    def field(self, name: str) -> "Location":
        return Location(self.base, self.in_storage, self.path + (Field(name),), self.variable)

    def fields(self, names: Iterable[str]) -> "Location":
        location = self
        for name in names:
            location = location.field(name)
        return location

    @property
    def term(self) -> str:
        """The key into mu or rho: the base with the field path appended."""
        fields = tuple(s.name for s in self.path if isinstance(s, Field))
        return ".".join((self.base,) + fields)

    @property
    def keys(self) -> tuple[z3.ExprRef, ...]:
        return tuple(s for s in self.path if not isinstance(s, Field))


def ensure(state: SymState, location: Location, leaf: z3.SortRef) -> None:
    """Create a memory term the first time it is touched, zero-initialised as Solidity does.

    Storage is never created here: every state variable is a free symbol made by
    `Machine.initial_state`, so a missing storage term is a bug, not an uninitialised value.
    """
    container = state.mu if location.in_storage else state.rho
    if location.term in container:
        return
    if location.in_storage:
        raise UnsupportedConstruct(f"no storage term named {location.term}")
    sort = leaf
    for key in reversed(location.keys):
        sort = z3.ArraySort(key.sort(), sort)
    container[location.term] = zero(sort)


def load(state: SymState, location: Location) -> z3.ExprRef:
    container = state.mu if location.in_storage else state.rho
    if location.term not in container:
        raise UnsupportedConstruct(f"read of {location.term}, which denotes no single value")
    term = container[location.term]
    for key in location.keys:
        term = z3.Select(term, key)
    return term


def store(state: SymState, location: Location, value: z3.ExprRef) -> None:
    container = state.mu if location.in_storage else state.rho
    if location.term not in container:
        raise UnsupportedConstruct(f"write to {location.term}, which denotes no single value")
    container[location.term] = _nested_store(container[location.term], location.keys, value)


def _nested_store(
    term: z3.ExprRef, keys: tuple[z3.ExprRef, ...], value: z3.ExprRef
) -> z3.ExprRef:
    if not keys:
        return value
    head, rest = keys[0], keys[1:]
    return z3.Store(term, head, _nested_store(z3.Select(term, head), rest, value))


# -------------------------------------------------------------------------- environment


@dataclass(frozen=True)
class Environment:
    """X_env of formula (2.3). `msg.data` is part of it -- see the note at ENV_VARIABLES."""

    sender: z3.BitVecRef
    origin: z3.BitVecRef
    value: z3.BitVecRef
    data: z3.ExprRef

    def terms(self) -> dict[str, z3.ExprRef]:
        return {SENDER: self.sender, ORIGIN: self.origin, VALUE: self.value, DATA: self.data}


def environment_constraints(environment: Environment) -> list[z3.BoolRef]:
    """What holds for X_env in any real transaction, regardless of who sends it.

    Only the bound on `msg.value` (see VALUE_BITS). `sender` and `origin` are constrained by the
    attacker model instead, and `msg.data` is opaque.

    Every state that starts a transaction must carry these: Sigma_0 here, and the state of the
    re-entered function g in week 4, whose `value_g` is a fresh symbol of its own.
    """
    return [z3.ULT(environment.value, z3.BitVecVal(2**VALUE_BITS, WORD_BITS))]


@dataclass(frozen=True)
class AttackerModel:
    """sender = a*, with a* different from every V_auth value and every address literal.

    Without it the solver would "confirm" an overflow inside an onlyOwner function by simply
    choosing sender = owner. K_addr is deliberately over-approximated to all address literals of
    the contract: that only shrinks the attacker's set of addresses, which is the safe direction.

    `origin` is left unconstrained on purpose: a tx.origin attack IS the tricked owner initiating
    the transaction.
    """

    auth: tuple[StateVariable, ...] = ()
    address_literals: tuple[int, ...] = ()

    @classmethod
    def build(
        cls, auth: Iterable[StateVariable], address_literals: Iterable[int]
    ) -> "AttackerModel":
        return cls(
            auth=tuple(sorted(auth, key=lambda v: v.canonical_name)),
            address_literals=tuple(sorted(address_literals)),
        )

    def constraints(self, state: SymState, environment: Environment) -> list[z3.BoolRef]:
        """Uses rho_0(u): call this on the INITIAL state, before any write to storage."""
        return [
            environment.sender != state.mu[variable.canonical_name]
            for variable in self.auth
            if variable.canonical_name in state.mu
        ] + [
            environment.sender != z3.BitVecVal(literal, ADDRESS_BITS)
            for literal in self.address_literals
        ]


# ------------------------------------------------------------------------------ machine


@dataclass
class Machine:
    """Z3 declarations shared by every path explored for one contract.

    Fresh names come from a counter, so two runs over the same contract build byte-identical
    formulas. Determinism is a requirement of the method, and a solver is very good at turning
    a nondeterministic name into a nondeterministic answer.
    """

    contract: Contract
    checked_arithmetic: bool  # Solidity >= 0.8
    _counter: itertools.count = field(default_factory=itertools.count, repr=False)
    _uninterpreted: dict[tuple, z3.FuncDeclRef] = field(default_factory=dict, repr=False)
    _literals: dict[str, z3.ExprRef] = field(default_factory=dict, repr=False)

    def fresh(self, name: str, sort: z3.SortRef) -> z3.ExprRef:
        return z3.Const(f"{name}!{next(self._counter)}", sort)

    def bytes_literal(self, text: str) -> z3.ExprRef:
        """A `bytes`/`string` literal: a distinct opaque constant, stable across paths."""
        if text not in self._literals:
            self._literals[text] = z3.Const(f"bytes!{len(self._literals)}", BYTES)
        return self._literals[text]

    def apply_uninterpreted(
        self, name: str, result: z3.SortRef, arguments: list[z3.ExprRef]
    ) -> z3.ExprRef:
        """An arbitrary function of its arguments -- keccak256 and the abi encoders.

        Same arguments give the same term, different arguments may give anything. That is
        exactly the assumption the method states for keccak256.
        """
        signature = (name, result, tuple(a.sort() for a in arguments))
        if signature not in self._uninterpreted:
            self._uninterpreted[signature] = z3.Function(
                f"{name}!{len(self._uninterpreted)}", *[a.sort() for a in arguments], result
            )
        return self._uninterpreted[signature](*arguments)

    def is_checked(self, node: Any) -> bool:
        """Does Solidity insert an overflow check here?

        Below 0.8 never; from 0.8 everywhere outside an `unchecked` block.
        """
        return self.checked_arithmetic and node.scope.is_checked

    # ------------------------------------------------------------------ initial state

    def new_environment(self) -> Environment:
        return Environment(
            sender=self.fresh(SENDER, z3.BitVecSort(ADDRESS_BITS)),
            origin=self.fresh(ORIGIN, z3.BitVecSort(ADDRESS_BITS)),
            value=self.fresh(VALUE, z3.BitVecSort(WORD_BITS)),
            data=self.fresh(DATA, BYTES),
        )

    def initial_state(self, entry_point: Function, environment: Environment) -> SymState:
        """Sigma_0 at the entry point: X_sto free, X_arg free, X_env bound to `environment`.

        PC starts with `environment_constraints`, not empty. The attacker model is NOT added here:
        it needs rho_0(u), so the caller adds it on the state this returns.
        """
        state = SymState()
        for variable in self.contract.state_variables:
            self._declare_storage(state, variable)
        for parameter in entry_point.parameters:
            state.rho[parameter.name] = self.fresh(parameter.name, sort_of(parameter.type))
        state.env.update(environment.terms())  # X_env lives outside rho (see SymState.env)
        state.pc.extend(environment_constraints(environment))
        return state

    def _declare_storage(self, state: SymState, variable: StateVariable) -> None:
        """One free symbol per leaf of the variable: a struct becomes a term per field.

        A type the method cannot model is skipped rather than fatal. Only the paths that read it
        are then abandoned, and a contract with one `bytes[]` member stays analysable.
        """
        try:
            leaves = flatten(variable.type)
        except UnsupportedConstruct:
            return
        for path, sort in leaves:
            name = ".".join((variable.name,) + path)
            state.mu[".".join((variable.canonical_name,) + path)] = self.fresh(name, sort)
