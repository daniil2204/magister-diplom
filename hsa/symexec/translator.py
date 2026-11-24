"""SlithIR operation -> state transformation (table 2.1).

One node at a time, in IR order. The translator is deliberately total in one direction only:
anything it does not model raises `UnsupportedConstruct`, the engine abandons that path and the
target ends as UNKNOWN with `unsupported_op`. Guessing a semantics would be worse than saying
"unknown", because a wrong transition turns into a wrong counterexample.

Arithmetic follows the method exactly:

* below Solidity 0.8 every operation is unchecked, so nothing is added to PC;
* from 0.8 on, outside an `unchecked` block, PC gains NOT Ovf -- the path that does not revert;
* Ovf for unsigned operands is written out as in chapter 2 rather than taken from a Z3 helper,
  so that the formula in the code and the formula in the thesis can be compared by eye.

Division and modulo add `y != 0` to PC in every version: division by zero reverts in all of
them, so the continuing path is the one where the divisor is non-zero.
"""

from __future__ import annotations

from typing import Optional

import z3
from slither.core.cfg.node import Node
from slither.core.declarations import Enum as SolidityEnum, SolidityVariable, SolidityVariableComposed
from slither.core.solidity_types import ArrayType, MappingType
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    Condition,
    Delete,
    EventCall,
    HighLevelCall,
    Index,
    LibraryCall,
    LowLevelCall,
    Member,
    NewStructure,
    Nop,
    Operation,
    Return,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion,
    Unary,
    UnaryType,
    Unpack,
)
from slither.slithir.variables import Constant, ReferenceVariable, TupleVariable

from hsa.model import Event, EventKind, ProgramPoint, SymState
from hsa.symexec.state import (
    ADDRESS_BITS,
    BYTES,
    WORD_BITS,
    Location,
    Machine,
    UnsupportedConstruct,
    contains_mapping,
    ensure,
    flatten,
    is_signed,
    load,
    sort_of,
    store,
    struct_of,
    zero,
)

#: Operations that can wrap, the ones Ovf is defined for in chapter 2.
WRAPPING = frozenset({BinaryType.ADDITION, BinaryType.SUBTRACTION, BinaryType.MULTIPLICATION})

#: Low-level call names that hand the caller's storage to the callee.
DELEGATECALL_NAMES = frozenset({"delegatecall", "callcode"})

#: Low-level calls that cannot write storage, so they cannot re-enter in the sense of SC08.
STATIC_CALL_NAMES = frozenset({"staticcall"})

_REQUIRE = ("require(bool)", "require(bool,string)", "assert(bool)")
_REVERT = ("revert()", "revert(string)", "revert()(string)")
_DESTRUCT = ("selfdestruct(address)", "suicide(address)")
_MODULAR = ("addmod(uint256,uint256,uint256)", "mulmod(uint256,uint256,uint256)")


def _word() -> z3.SortRef:
    return z3.BitVecSort(WORD_BITS)


def _address() -> z3.SortRef:
    return z3.BitVecSort(ADDRESS_BITS)


#: Built-ins modelled as uninterpreted functions of their arguments: same arguments give the same
#: term, different arguments may give anything. The list is closed and enumerated rather than
#: matched by prefix, because the thesis carries exactly this list -- a rule like "keccak256 and
#: similar" would not say which contracts the method can and cannot handle.
#:
#: Three groups, with different reasons for being uninterpreted:
#:
#: * hashes and `ecrecover` -- the method's stated assumption about keccak256, extended to the
#:   other pre-compiles, which are equally out of reach for a bitvector solver;
#: * the abi encoders and `code` -- their result is a `bytes` value the method never inspects;
#: * `balance`, `gasleft`, `blockhash` -- values the environment chooses and the attacker does
#:   not, so they are free, but fixed for one transaction.
#:
#: `addmod` and `mulmod` are NOT here: they are deterministic and `_do_modular` computes them
#: exactly in double width.
UNINTERPRETED: dict[str, "z3.SortRef"] = {
    signature: sort
    for signature, sort in [
        ("keccak256()", _word()),
        ("keccak256(bytes)", _word()),
        ("sha3()", _word()),
        ("sha256()", _word()),
        ("sha256(bytes)", _word()),
        ("ripemd160()", _word()),
        ("ripemd160(bytes)", _word()),
        ("ecrecover()", _address()),
        ("ecrecover(bytes32,uint8,bytes32,bytes32)", _address()),
        ("abi.encode()", BYTES),
        ("abi.encodePacked()", BYTES),
        ("abi.encodeWithSelector()", BYTES),
        ("abi.encodeWithSignature()", BYTES),
        ("abi.encodeCall()", BYTES),
        ("abi.decode()", BYTES),
        ("bytes.concat()", BYTES),
        ("code(address)", BYTES),
        ("codehash(address)", _word()),
        ("balance(address)", _word()),
        ("balance(uint256)", _word()),
        ("this.balance()", _word()),
        ("selfbalance()", _word()),
        ("gasleft()", _word()),
        ("blockhash(uint256)", _word()),
    ]
}


# ------------------------------------------------------------------------------- values


def value_of(machine: Machine, state: SymState, point: ProgramPoint, variable) -> z3.ExprRef:
    """The Z3 term of a SlithIR variable, creating a symbol the first time it is needed."""
    if isinstance(variable, Constant):
        return _constant(machine, variable)
    if isinstance(variable, ReferenceVariable):
        location = _location(state, variable)
        ensure(state, location, sort_of(variable.type))  # refuses a struct: it has no value
        if location.in_storage:
            _record(state, point, EventKind.READ, variable=location.variable)
        return load(state, location)
    if isinstance(variable, StateVariable):
        if variable.canonical_name not in state.mu:
            raise UnsupportedConstruct(f"{variable.canonical_name} denotes no single value")
        _record(state, point, EventKind.READ, variable=variable)
        return state.mu[variable.canonical_name]
    if isinstance(variable, (SolidityVariable, SolidityVariableComposed)):
        return _solidity_variable(machine, state, variable)
    name = variable.name
    if name not in state.rho:
        # A local declared but not assigned. Solidity zero-initialises it; the parameters of the
        # entry point are already free symbols in rho.
        state.rho[name] = zero(sort_of(variable.type))
    return state.rho[name]


def _constant(machine: Machine, variable: Constant) -> z3.ExprRef:
    value = variable.value
    if isinstance(value, bool):
        return z3.BoolVal(value)
    if isinstance(value, int):
        sort = sort_of(variable.type)
        if isinstance(sort, z3.BitVecSortRef):
            return z3.BitVecVal(value, sort.size())
        raise UnsupportedConstruct(f"integer literal of type {variable.type!r}")
    if isinstance(value, str):
        return machine.bytes_literal(value)
    raise UnsupportedConstruct(f"literal {value!r}")


def _solidity_variable(machine: Machine, state: SymState, variable) -> z3.ExprRef:
    """X_env is bound by the initial state; everything else is a free symbol of the transaction.

    `block.timestamp` and friends keep one symbol for the whole path, which is what they are: a
    value the attacker does not choose but which is fixed once the transaction runs. They live in
    `state.env`, not rho, so saving and restoring a call frame leaves them alone.
    """
    name = str(variable)
    if name not in state.env:
        state.env[name] = machine.fresh(name, sort_of(variable.type))
    return state.env[name]


def _location(state: SymState, variable: ReferenceVariable) -> Location:
    location = state.rho.get(variable.name)
    if not isinstance(location, Location):
        raise UnsupportedConstruct(f"reference {variable.name} used before it was formed")
    return location


def _base_location(state: SymState, variable) -> Location:
    """The place a SlithIR variable denotes, for Index and Member to extend.

    A local may hold a Location rather than a term: that is a `storage` pointer, and indexing or
    reaching into it must land on the storage it points at, not on a copy.
    """
    if isinstance(variable, ReferenceVariable):
        return _location(state, variable)
    if isinstance(variable, StateVariable):
        return Location(variable.canonical_name, True, (), variable)
    existing = state.rho.get(variable.name)
    if isinstance(existing, Location):
        return existing
    return Location(variable.name, False, ())


# ------------------------------------------------------------------------------ writing


def assign(
    machine: Machine, state: SymState, point: ProgramPoint, destination, term: z3.ExprRef
) -> None:
    if isinstance(destination, ReferenceVariable):
        location = _location(state, destination)
        ensure(state, location, term.sort())
        store(state, location, term)
        if location.in_storage:
            _record(state, point, EventKind.WRITE, variable=location.variable)
        return
    if isinstance(destination, StateVariable):
        state.mu[destination.canonical_name] = term
        _record(state, point, EventKind.WRITE, variable=destination)
        return
    state.rho[destination.name] = term


def _record(state: SymState, point: ProgramPoint, kind: EventKind, **fields) -> None:
    state.tau.append(Event(kind=kind, point=point, **fields))


# --------------------------------------------------------------------------- arithmetic


def overflow_condition(
    operation: BinaryType, left: z3.BitVecRef, right: z3.BitVecRef, signed: bool
) -> z3.BoolRef:
    """Ovf_op(x, y) of chapter 2.

    The unsigned forms are the ones written in the thesis:
        +  x + y <u x
        -  x <u y
        *  y != 0 AND (x*y) /u y != x

    The signed forms are, for an N-bit operand and sign extension to 2N bits,

        Ovf_op(x, y)  <=>  ext(x) op ext(y) != ext(x op y)

    that is: the operation overflows exactly when the N-bit result differs from the exact one.
    `_signed_overflow` below computes this with Z3's own predicates, which are cheaper for the
    solver; `test_signed_overflow_matches_the_double_width_definition` proves the two agree on
    every pair of 8-bit values.
    """
    if signed:
        return _signed_overflow(operation, left, right)
    if operation is BinaryType.ADDITION:
        return z3.ULT(left + right, left)
    if operation is BinaryType.SUBTRACTION:
        return z3.ULT(left, right)
    if operation is BinaryType.MULTIPLICATION:
        # Equivalent to the thesis form `y != 0 AND (x*y) /u y != x`, but Z3's native predicate
        # avoids an unsigned division. UDiv is costly to bit-blast, and the strong overflow
        # condition quantifies over this term; the two agree on every pair of bits, which
        # `test_overflow_condition_matches_the_thesis_formulas` checks.
        return z3.Not(z3.BVMulNoOverflow(left, right, False))
    raise UnsupportedConstruct(f"no Ovf for {operation}")


def double_width_overflow(
    operation: BinaryType, left: z3.BitVecRef, right: z3.BitVecRef, signed: bool
) -> z3.BoolRef:
    """Ovf written directly: the N-bit result differs from the one computed in 2N bits.

    This is the definition; `overflow_condition` is the implementation. Keeping both lets a test
    prove they agree instead of asking the reader to trust a hand-derived formula.
    """
    width = left.size()
    extend = z3.SignExt if signed else z3.ZeroExt
    exact = _arithmetic(operation, extend(width, left), extend(width, right), signed)
    return exact != extend(width, _arithmetic(operation, left, right, signed))


def _signed_overflow(
    operation: BinaryType, left: z3.BitVecRef, right: z3.BitVecRef
) -> z3.BoolRef:
    if operation is BinaryType.ADDITION:
        return z3.Or(
            z3.Not(z3.BVAddNoOverflow(left, right, True)),
            z3.Not(z3.BVAddNoUnderflow(left, right)),
        )
    if operation is BinaryType.SUBTRACTION:
        return z3.Or(
            z3.Not(z3.BVSubNoOverflow(left, right)),
            z3.Not(z3.BVSubNoUnderflow(left, right, True)),
        )
    if operation is BinaryType.MULTIPLICATION:
        return z3.Or(
            z3.Not(z3.BVMulNoOverflow(left, right, True)),
            z3.Not(z3.BVMulNoUnderflow(left, right)),
        )
    raise UnsupportedConstruct(f"no Ovf for {operation}")


def _match_width(left: z3.ExprRef, right: z3.ExprRef, signed: bool) -> tuple[z3.ExprRef, z3.ExprRef]:
    """Literals come out of SlithIR in their declared width; widen the narrower operand."""
    if not isinstance(left, z3.BitVecRef) or not isinstance(right, z3.BitVecRef):
        return (left, right)
    difference = left.size() - right.size()
    if difference == 0:
        return (left, right)
    extend = z3.SignExt if signed else z3.ZeroExt
    if difference > 0:
        return (left, extend(difference, right))
    return (extend(-difference, left), right)


def _arithmetic(operation: BinaryType, left, right, signed: bool) -> z3.ExprRef:
    if operation is BinaryType.ADDITION:
        return left + right
    if operation is BinaryType.SUBTRACTION:
        return left - right
    if operation is BinaryType.MULTIPLICATION:
        return left * right
    if operation is BinaryType.DIVISION:
        return left / right if signed else z3.UDiv(left, right)
    if operation is BinaryType.MODULO:
        return z3.SRem(left, right) if signed else z3.URem(left, right)
    raise UnsupportedConstruct(f"arithmetic {operation}")


def _comparison(operation: BinaryType, left, right, signed: bool) -> z3.BoolRef:
    if operation is BinaryType.EQUAL:
        return left == right
    if operation is BinaryType.NOT_EQUAL:
        return left != right
    if not isinstance(left, z3.BitVecRef):
        raise UnsupportedConstruct(f"ordering {operation} on {left.sort()}")
    ordered = {
        BinaryType.LESS: (z3.ULT, lambda a, b: a < b),
        BinaryType.LESS_EQUAL: (z3.ULE, lambda a, b: a <= b),
        BinaryType.GREATER: (z3.UGT, lambda a, b: a > b),
        BinaryType.GREATER_EQUAL: (z3.UGE, lambda a, b: a >= b),
    }[operation]
    return ordered[1](left, right) if signed else ordered[0](left, right)


def _bitwise(operation: BinaryType, left, right, signed: bool) -> z3.ExprRef:
    if operation is BinaryType.AND:
        return z3.And(left, right) if z3.is_bool(left) else left & right
    if operation is BinaryType.OR:
        return z3.Or(left, right) if z3.is_bool(left) else left | right
    if operation is BinaryType.CARET:
        return z3.Xor(left, right) if z3.is_bool(left) else left ^ right
    if operation is BinaryType.ANDAND:
        return z3.And(left, right)
    if operation is BinaryType.OROR:
        return z3.Or(left, right)
    if operation is BinaryType.LEFT_SHIFT:
        return left << right
    if operation is BinaryType.RIGHT_SHIFT:
        return left >> right if signed else z3.LShR(left, right)
    raise UnsupportedConstruct(f"operator {operation}")


def _power(left, right) -> z3.ExprRef:
    """Only a literal exponent, unrolled into multiplications: Z3 has no bitvector power."""
    if not z3.is_bv_value(right):
        raise UnsupportedConstruct("x ** y with a symbolic exponent")
    exponent = right.as_long()
    if exponent > 64:
        raise UnsupportedConstruct(f"x ** {exponent} would unroll into {exponent} products")
    result = z3.BitVecVal(1, left.size())
    for _ in range(exponent):
        result = result * left
    return result


# -------------------------------------------------------------------------- the handlers


def execute_node(machine: Machine, state: SymState, node: Node) -> None:
    """Apply every operation of the node to the state, in IR order."""
    for index, ir in enumerate(node.irs):
        execute(machine, state, ProgramPoint(node.function, node, index), ir)


def execute(machine: Machine, state: SymState, point: ProgramPoint, ir: Operation) -> None:
    handler = _HANDLERS.get(type(ir))
    if handler is None:
        raise UnsupportedConstruct(f"{type(ir).__name__}: {ir}")
    handler(machine, state, point, ir)


def condition_of(machine: Machine, state: SymState, node: Node) -> z3.BoolRef:
    """The term an IF / IFLOOP branches on. The engine forks on it; PC is not touched here.

    Call this AFTER `execute_node` on the same node. A branching node carries the operations that
    build the condition as well as the Condition marker itself -- `if (credit[x] >= v)` is Index,
    Binary and Condition in one node -- so the marker only names a variable that the preceding
    operations must already have put into rho.
    """
    for index, ir in enumerate(node.irs):
        if isinstance(ir, Condition):
            return value_of(machine, state, ProgramPoint(node.function, node, index), ir.value)
    raise UnsupportedConstruct(f"branching node {node.node_id} without a Condition")


def _do_assignment(machine, state, point, ir: Assignment) -> None:
    if struct_of(ir.rvalue.type) is not None:
        _assign_struct(machine, state, point, ir)
        return
    assign(machine, state, point, ir.lvalue, value_of(machine, state, point, ir.rvalue))


def _assign_struct(machine, state, point, ir: Assignment) -> None:
    """`Account x = accounts[k]`: a reference if x is `storage`, a copy if it is `memory`.

    SlithIR spells the two identically -- the only difference is the declared data location -- and
    the difference decides whether a later `x.balance = 0` reaches storage at all. Getting it
    wrong would invent or lose a write after an external call, i.e. an SC08 verdict.
    """
    source = _base_location(state, ir.rvalue)
    destination = ir.lvalue
    if isinstance(destination, LocalVariable) and destination.location == "storage":
        state.rho[destination.name] = source
        return
    _copy_struct(state, point, source, _base_location(state, destination), ir.rvalue.type)


def _copy_struct(state, point, source: Location, destination: Location, type_) -> None:
    """Copy a struct leaf by leaf. Flattening makes this the only way to move a struct value."""
    if contains_mapping(type_):
        raise UnsupportedConstruct(f"copying struct {type_} would have to copy a mapping")
    for path, sort in flatten(type_):
        origin, target = source.fields(path), destination.fields(path)
        ensure(state, origin, sort)
        term = load(state, origin)
        if origin.in_storage:
            _record(state, point, EventKind.READ, variable=origin.variable)
        ensure(state, target, sort)
        store(state, target, term)
        if target.in_storage:
            _record(state, point, EventKind.WRITE, variable=target.variable)


def _do_member(machine, state, point, ir: Member) -> None:
    """`x.f`: one more step in a location path for a struct field, or an enum constant.

    The field does not become a Z3 key -- it picks the flattened term (see `Location`), which is
    what makes a write to `.nonce` invisible to a read of `.balance`.
    """
    name = ir.variable_right.value if isinstance(ir.variable_right, Constant) else None
    if isinstance(name, str) and struct_of(getattr(ir.variable_left, "type", None)) is not None:
        state.rho[ir.lvalue.name] = _base_location(state, ir.variable_left).field(name)
        return
    if isinstance(name, str) and isinstance(ir.variable_left, SolidityEnum):
        values = ir.variable_left.values
        if name in values:
            assign(machine, state, point, ir.lvalue, z3.BitVecVal(values.index(name), WORD_BITS))
            return
    raise UnsupportedConstruct(f"member access {ir}")


def _do_new_structure(machine, state, point, ir: NewStructure) -> None:
    """`Account(a, b)`: a fresh memory record, arguments in declaration order."""
    destination = Location(ir.lvalue.name, False, ())
    for element, argument in zip(ir.structure.elems_ordered, ir.arguments):
        target = destination.field(element.name)
        if struct_of(element.type) is not None:
            _copy_struct(state, point, _base_location(state, argument), target, element.type)
            continue
        sort = sort_of(element.type)
        ensure(state, target, sort)
        store(state, target, _convert(value_of(machine, state, point, argument), sort))


def _do_binary(machine, state, point, ir: Binary) -> None:
    signed = is_signed(ir.variable_left.type) or is_signed(ir.variable_right.type)
    left = value_of(machine, state, point, ir.variable_left)
    right = value_of(machine, state, point, ir.variable_right)
    left, right = _match_width(left, right, signed)
    operation = ir.type

    if operation in WRAPPING:
        result = _arithmetic(operation, left, right, signed)
        if machine.is_checked(point.node):
            state.pc.append(z3.Not(overflow_condition(operation, left, right, signed)))
        else:
            _record(state, point, EventKind.UNCHECKED_OP)
    elif operation in (BinaryType.DIVISION, BinaryType.MODULO):
        state.pc.append(right != 0)  # division by zero reverts in every Solidity version
        result = _arithmetic(operation, left, right, signed)
    elif operation is BinaryType.POWER:
        result = _power(left, right)
    elif operation in (
        BinaryType.LESS,
        BinaryType.LESS_EQUAL,
        BinaryType.GREATER,
        BinaryType.GREATER_EQUAL,
        BinaryType.EQUAL,
        BinaryType.NOT_EQUAL,
    ):
        result = _comparison(operation, left, right, signed)
    else:
        result = _bitwise(operation, left, right, signed)

    assign(machine, state, point, ir.lvalue, result)


def _do_unary(machine, state, point, ir: Unary) -> None:
    operand = value_of(machine, state, point, ir.rvalue)
    if ir.type is UnaryType.BANG:
        result = z3.Not(operand)
    elif ir.type is UnaryType.TILD:
        result = ~operand
    else:
        raise UnsupportedConstruct(f"unary {ir.type}")
    assign(machine, state, point, ir.lvalue, result)


def _do_index(machine, state, point, ir: Index) -> None:
    key = value_of(machine, state, point, ir.variable_right)
    collection = ir.variable_left
    state.rho[ir.lvalue.name] = _base_location(state, collection).index(
        _index_key(key, getattr(collection, "type", None))
    )


def _index_key(key: z3.ExprRef, collection_type) -> z3.ExprRef:
    """Widen the key to the declared key type.

    SlithIR keeps a literal in its own width, so `balances[0]` would otherwise select a
    `BitVec(8)` out of an `Array(BitVec(256), ...)`.
    """
    if isinstance(collection_type, MappingType):
        return _convert(key, sort_of(collection_type.type_from))
    if isinstance(collection_type, ArrayType):
        return _convert(key, z3.BitVecSort(WORD_BITS))
    return key


def _do_delete(machine, state, point, ir: Delete) -> None:
    """`delete x`: zero the place x denotes.

    The operand is `ir.variable`. `ir.lvalue` is the outermost container Slither reports as
    written -- for `delete balances[k]` that is `balances` itself, so deleting through the lvalue
    would clear every key of the mapping instead of one.
    """
    target = ir.variable
    if struct_of(target.type) is not None:
        _delete_struct(state, point, _base_location(state, target), target.type)
        return
    if isinstance(target, ReferenceVariable):
        location = _location(state, target)
        ensure(state, location, sort_of(target.type))
        assign(machine, state, point, target, zero(load(state, location).sort()))
        return
    assign(machine, state, point, target, zero(sort_of(target.type)))


def _delete_struct(state, point, location: Location, type_) -> None:
    """`delete s`: zero every field.

    A struct holding a mapping is refused: Solidity leaves such a mapping untouched, and the
    method does not model that (it stays in the `unsupported_op` list).
    """
    if contains_mapping(type_):
        raise UnsupportedConstruct(f"delete of struct {type_}, which holds a mapping")
    for path, sort in flatten(type_):
        leaf = location.fields(path)
        ensure(state, leaf, sort)
        store(state, leaf, zero(load(state, leaf).sort()))
        if leaf.in_storage:
            _record(state, point, EventKind.WRITE, variable=leaf.variable)


def _do_conversion(machine, state, point, ir: TypeConversion) -> None:
    term = value_of(machine, state, point, ir.variable)
    assign(machine, state, point, ir.lvalue, _convert(term, sort_of(ir.type)))


def _convert(term: z3.ExprRef, target: z3.SortRef) -> z3.ExprRef:
    if term.sort() == target:
        return term
    if isinstance(term, z3.BitVecRef) and isinstance(target, z3.BitVecSortRef):
        difference = target.size() - term.size()
        if difference > 0:
            return z3.ZeroExt(difference, term)
        return z3.Extract(target.size() - 1, 0, term)
    raise UnsupportedConstruct(f"conversion {term.sort()} -> {target}")


def _do_solidity_call(machine, state, point, ir: SolidityCall) -> None:
    name = ir.function.full_name
    arguments = [value_of(machine, state, point, a) for a in ir.arguments]
    if name in _REQUIRE:
        state.pc.append(arguments[0])
        return
    if name in _REVERT:
        state.pc.append(z3.BoolVal(False))  # this path does not exist
        return
    if name in _DESTRUCT:
        _record(state, point, EventKind.PRIV, destination=ir.arguments[0])
        return
    if name in _MODULAR:
        _do_modular(machine, state, point, ir, name, arguments)
        return
    if name in UNINTERPRETED:
        result = machine.apply_uninterpreted(name, UNINTERPRETED[name], arguments)
        assign(machine, state, point, ir.lvalue, result)
        return
    raise UnsupportedConstruct(f"solidity call {name}")


def _do_modular(machine, state, point, ir: SolidityCall, name: str, arguments) -> None:
    """`addmod(x, y, k)` and `mulmod(x, y, k)`: exact, in double width.

    Both are defined on the integers and only then reduced, so x + y and x * y must not wrap --
    which is why the operands are widened to 2N bits first. Modelling them as uninterpreted
    functions would be sound but would lose a value the contract computes exactly.

    k = 0 reverts, like any other division by zero.
    """
    width = arguments[2].size()
    wide = [z3.ZeroExt(width, term) for term in arguments]
    exact = wide[0] + wide[1] if name == _MODULAR[0] else wide[0] * wide[1]
    state.pc.append(arguments[2] != 0)
    result = z3.Extract(width - 1, 0, z3.URem(exact, wide[2]))
    assign(machine, state, point, ir.lvalue, result)


def _do_low_level_call(machine, state, point, ir: LowLevelCall) -> None:
    """An external call: an event plus a fresh symbol for everything it returns (table 2.1).

    `staticcall` cannot write storage, so it cannot re-enter in the sense SC08 is about.
    """
    name = str(ir.function_name)
    kind = EventKind.DCALL if name in DELEGATECALL_NAMES else EventKind.LCALL
    destination = value_of(machine, state, point, ir.destination)
    call_value = (
        value_of(machine, state, point, ir.call_value) if ir.call_value is not None else None
    )
    result = _bind_call_result(machine, state, ir.lvalue, [z3.BoolSort(), BYTES])
    _record(
        state,
        point,
        kind,
        destination=destination,
        value=call_value,
        result=result,
        can_reenter=name not in STATIC_CALL_NAMES,
        snapshot=state.fork(),
    )


def _do_high_level_call(machine, state, point, ir: HighLevelCall) -> None:
    """A typed call through an interface. Never LCALL: a failed one reverts on its own.

    Treating it as a low-level call would let phi_UC (2.7) fire on an ordinary `token.transfer(x)`
    whose return value Solidity itself checks -- a false positive the static stage never produces,
    because SC06 is raised only for LowLevelCall and Send.
    """
    destination = value_of(machine, state, point, ir.destination)
    call_value = (
        value_of(machine, state, point, ir.call_value) if ir.call_value is not None else None
    )
    _record(
        state,
        point,
        EventKind.CALL,
        destination=destination,
        value=call_value,
        can_reenter=True,
        snapshot=state.fork(),
    )
    _bind_call_result(machine, state, ir.lvalue, None)


def _do_library_call(machine, state, point, ir: HighLevelCall) -> None:
    """A call to a library function.

    An *internal* library function is compiler-inlined, and the engine walks into its body, so it
    never reaches the translator. Only a *public* or *external* one does: that is a DELEGATECALL to a
    separate library contract whose code is unknown, so its result is opaque -- a fresh symbol, as for
    any external call. No reentrant CALL event is recorded: the library address is a constant, not an
    attacker-chosen one, so the call is neither an SC08 nor an SC10 source.
    """
    _bind_call_result(machine, state, ir.lvalue, None)


def _do_transfer(machine, state, point, ir) -> None:
    """`transfer` and `send` move ether but cannot re-enter: 2300 gas buys no storage write.

    They differ in what they do on failure, and the method cares about the difference: `transfer`
    reverts, while `send` hands back a success flag that the caller may ignore. So `send` is an
    LCALL carrying r_i -- that is exactly the `unchecked-send` case of SC06 -- and `transfer` is
    a plain CALL. Neither may re-enter.
    """
    destination = value_of(machine, state, point, ir.destination)
    call_value = value_of(machine, state, point, ir.call_value)
    if isinstance(ir, Send):
        result = _bind_call_result(machine, state, ir.lvalue, None)
        _record(
            state,
            point,
            EventKind.LCALL,
            destination=destination,
            value=call_value,
            result=result,
            can_reenter=False,
            snapshot=state.fork(),
        )
        return
    _record(
        state,
        point,
        EventKind.CALL,
        destination=destination,
        value=call_value,
        can_reenter=False,
        snapshot=state.fork(),
    )


def _bind_call_result(
    machine: Machine, state: SymState, lvalue, sorts: Optional[list[z3.SortRef]]
) -> Optional[z3.ExprRef]:
    """The callee is unknown code, so whatever it returns is a fresh symbol.

    Returns r_i -- the success flag -- when the call has one, so that the event can carry it.
    SlithIR spells the same low-level call two ways: `(bool ok, ) = a.call(...)` gives a
    TupleVariable, while the 0.4 form `bool ok = a.call.value(v)()` gives a plain boolean.
    """
    if lvalue is None:
        return None
    if isinstance(lvalue, TupleVariable):
        components = sorts or [sort_of(t) for t in lvalue.type]
        terms = [machine.fresh("ret", sort) for sort in components]
        state.rho[lvalue.name] = terms
        return terms[0] if terms and terms[0].sort() == z3.BoolSort() else None
    term = machine.fresh("ret", sort_of(lvalue.type))
    state.rho[lvalue.name] = term
    return term if term.sort() == z3.BoolSort() else None


def _do_unpack(machine, state, point, ir: Unpack) -> None:
    components = state.rho.get(ir.tuple.name)
    if not isinstance(components, list):
        raise UnsupportedConstruct(f"unpack of {ir.tuple.name}, which is not a tuple here")
    state.rho[ir.lvalue.name] = components[ir.index]


def return_slot(function) -> str:
    """The rho key under which a function stashes its returned value(s).

    An internal call is inlined by the ICFG as the callee's own vertices; the engine, when it walks
    the return edge, reads this slot and binds it to the caller's lvalue. The key is per-function so
    that a return inside a callee does not clash with one in the caller on the same path.
    """
    return f"<return>{function.canonical_name}"


def _do_return(machine, state, point, ir: Return) -> None:
    """Stash the returned value(s) so the engine can propagate them to the caller's lvalue.

    A bare `return;` carries no values and leaves no slot. One value is stored directly; several are
    stored as a list, mirroring how a tuple is held in rho for `Unpack` to read back.
    """
    values = list(ir.values)
    if not values:
        return
    terms = [value_of(machine, state, point, value) for value in values]
    state.rho[return_slot(point.function)] = terms[0] if len(terms) == 1 else terms


def _ignore(machine, state, point, ir) -> None:
    """Operations with no effect on <rho, mu, PC>: logs, the condition marker, nops.

    The branch of a Condition is taken by the engine through `condition_of`.
    """


_HANDLERS = {
    Assignment: _do_assignment,
    Binary: _do_binary,
    Unary: _do_unary,
    Index: _do_index,
    Member: _do_member,
    NewStructure: _do_new_structure,
    Delete: _do_delete,
    TypeConversion: _do_conversion,
    SolidityCall: _do_solidity_call,
    LowLevelCall: _do_low_level_call,
    HighLevelCall: _do_high_level_call,
    LibraryCall: _do_library_call,
    Transfer: _do_transfer,
    Send: _do_transfer,
    Unpack: _do_unpack,
    Condition: _ignore,
    EventCall: _ignore,
    Return: _do_return,
    Nop: _ignore,
}
