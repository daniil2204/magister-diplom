"""Directed symbolic execution of one target (figure 2.2).

The static stage hands the engine a target `t`: a node, a class and the entry point it is reached
from. The engine explores only the paths of that entry point that can reach the node, and returns
one `Outcome` -- CONFIRMED with a counterexample, REFUTED, or UNKNOWN with a reason.

What this module does: the single-target search for the five straight-line classes AC, TO, DC, UC
and OV, plus SC08 reentrancy through the one-level re-entry model of `hsa.symexec.reentry`
(`analyze_target`), and the per-contract orchestration on top of it (`analyze_targets`) -- the P(t)
priority queue, the budget B_t carried along it, and the skipping of nodes already confirmed from
another entry point.

How the search runs:

* the graph is the interprocedural expansion already built by `hsa.icfg` from the entry point, so
  modifiers and inlined calls are walked rather than re-derived. An inlined call (`inlined_callee`:
  an ordinary internal call, or a call to an *internal* library function such as SafeMath) is not
  translated in place; instead its arguments are bound to the callee's parameters and the IR is
  skipped, because the ICFG has already routed control into the callee's body. A public or external
  library call stays opaque and is translated as any external call;
* N*_t (2.19) is the set of vertices from which the target is reachable. Outside M3 the search is
  pruned to it and ordered by distance to the target; M3 keeps the whole graph and walks it DFS;
* a loop is bounded by entering any vertex at most `k_unroll` times per path. Overflow_loop is the
  witness: the body overflows only on the second iteration, so k = 1 is REFUTED and k = 2 CONFIRMED;
* the predicate is evaluated on the state positioned just BEFORE the target operation, i.e. after
  the operations of the node up to `op_index`. Reaching the target never ends the path -- only a
  CONFIRMED does -- so the second iteration of a loop is still explored after the first was refuted.

Inlined calls become the callee's own vertices, so the engine does not translate the call IR. It
keeps call frames along each path instead, at the two edges the expansion already draws:

* on a call edge (a vertex gains a frame) it snapshots rho, then binds the arguments to the
  callee's parameters -- so a local `a` in the callee does not clobber a local `a` in the caller;
* on a return edge (frames are popped) it reads the value the callee stashed under `return_slot`,
  restores the snapshot, and binds that value to the call's lvalue -- so `s = add(a, b)` carries the
  real sum back, not a free symbol. A `SafeMath`-style `balances[x] = balances[x].sub(v)` therefore
  writes the exact difference and the following path sees it.

A node may hold more than one inlined call -- a chain `a.add(b).sub(c)` is two library calls in one
node. The ICFG returns from each call to the same node at the index after it (the vertex's `resume`),
so the calls are taken left to right, each one's result bound before the next one's arguments are
read, and the operations after the last call run once.

A recursive internal call is not inlined by the ICFG (the ordinary edge is kept, 2.19), so the
engine cannot model the recursive activation; such a path ends UNKNOWN `recursion` rather than
silently continuing as if the call had not happened.

The analysis never raises: `UnsupportedConstruct` on a path abandons that path as UNKNOWN
`unsupported_op`, and the per-target time budget turns into UNKNOWN `timeout`.
"""

from __future__ import annotations

import random
import time
from typing import TYPE_CHECKING, Callable, Iterator, NamedTuple, Optional

import z3
from slither.core.cfg.node import Node, NodeType
from slither.core.declarations import Function
from slither.slithir.operations import InternalCall

from hsa.config import Config, VulnClass
from hsa.icfg import inlined_callee, next_inlined_call
from hsa.model import ProgramPoint, SymState, TargetResult, UnknownReason, Verdict
from hsa.priority import budgets, order, priority, risk
from hsa.symexec.predicates import (
    Outcome,
    Probe,
    _reachability,
    check_access,
    check_delegatecall,
    check_overflow,
    check_tx_origin,
    check_unchecked,
)
from hsa.symexec.reentry import check_reentrancy
from hsa.symexec.state import AttackerModel, Machine, UnsupportedConstruct
from hsa.symexec.translator import condition_of, execute, return_slot, value_of

if TYPE_CHECKING:  # pragma: no cover - typing only
    from hsa.icfg import Expansion, Frame, Vertex
    from hsa.model import Target
    from hsa.static.base import Analysis

_INFINITY = float("inf")


class _Save(NamedTuple):
    """What a path must remember to return from one inlined internal call.

    `rho` is the caller's variable map captured just before the arguments were bound; `callee` is the
    callee function, needed to read its `return_slot` on the way back; `site` is the caller node that
    held the call and `index` the position of the `InternalCall` in it, so that the operations that
    follow the call in the same node -- `s := TMP` after `TMP = f(...)`, and the overflow that reads
    `s` -- run only once the result is bound, not before.
    """

    frame: "Frame"
    rho: dict
    callee: Function
    site: Node
    index: int


def analyze_target(
    analysis: "Analysis", target: "Target", config: Config, budget: Optional[float] = None
) -> Outcome:
    """Explore the paths of `target.entry_point` that reach the target and return one verdict.

    `budget` is the time, in seconds, this target may use; it defaults to the reference cap used by
    the offline replay. Running out of it is UNKNOWN `timeout`, not a wrong verdict.
    """
    budget = config.reference_cap if budget is None else budget
    expansion = analysis.expansions[target.entry_point.canonical_name]
    occurrences = expansion.vertices_of(target.point.node)
    targets = [v for v in occurrences if v.depth <= config.d_inline]
    if not targets:
        # The node is reached only through an inlining chain longer than d (2.19).
        return Outcome(Verdict.UNKNOWN, UnknownReason.DEPTH_EXCEEDED)

    machine = Machine(analysis.contract, analysis.compilation.checked_arithmetic)
    environment = machine.new_environment()
    state = machine.initial_state(target.entry_point, environment)
    attacker = AttackerModel.build(analysis.auth, analysis.address_literals)
    state.pc.extend(attacker.constraints(state, environment))
    controlled = tuple(environment.terms().values()) + tuple(
        state.rho[p.name] for p in target.entry_point.parameters if p.name in state.rho
    )

    target_set = set(targets)
    nstar: set["Vertex"] = set()
    distances: dict["Vertex", int] = {}
    for vertex in targets:
        nstar |= expansion.backward_reachable(vertex)
        for node, distance in expansion.distances_to(vertex).items():
            if node not in distances or distance < distances[node]:
                distances[node] = distance

    return _search(
        machine,
        environment,
        controlled,
        analysis,
        target,
        config,
        budget,
        expansion,
        target_set,
        nstar,
        distances,
        state,
    )


#: A runner analyses one target and reports (outcome, seconds spent). Injectable so the queue
#: orchestration can be tested without real symbolic execution or a wall clock.
TargetRunner = Callable[["Analysis", "Target", Config, float], tuple[Outcome, float]]


def _run_target(
    analysis: "Analysis", target: "Target", config: Config, budget: float
) -> tuple[Outcome, float]:
    """`analyze_target` wrapped with timing and the never-raise guarantee.

    Any exception becomes UNKNOWN `analysis_error`, so one bad target never stops the queue.
    """
    started = time.monotonic()
    try:
        outcome = analyze_target(analysis, target, config, budget=budget)
    except Exception:  # noqa: BLE001 - the queue must survive any single-target failure
        outcome = Outcome(Verdict.UNKNOWN, UnknownReason.ANALYSIS_ERROR)
    return outcome, time.monotonic() - started


def _queue(targets: list["Target"], config: Config) -> list["Target"]:
    """The order targets are taken from the queue in.

    Outside M4 this is descending P(t) with a deterministic tie-break (`priority.order`). M4
    replaces it with a seeded shuffle of a deterministically sorted base, so the random order is
    still reproducible from the seed.
    """
    if config.priority_ordered:
        return order(targets, config)
    base = sorted(targets, key=lambda t: (str(t.point), t.entry_point.canonical_name))
    random.Random(config.seed).shuffle(base)
    return base


def analyze_targets(
    pairs: list[tuple["Analysis", "Target"]],
    config: Config,
    budget: Optional[float] = None,
    static_elapsed: float = 0.0,
    runner: Optional[TargetRunner] = None,
) -> list[TargetResult]:
    """Run the whole target queue of one contract file under one budget (2.18).

    `pairs` are the (analysis, target) pairs of every analysed contract in the file: the queue and
    the budget are shared across them, because B of (2.18) is a per-*contract-file* budget. The
    targets are taken in P(t) order (seeded random under M4). Each is granted its own B_t plus the
    time earlier targets left unused -- a running `bank` -- so an early verdict lets a later, harder
    target spend past its own B_t (2.18, "unused time passes further along the queue"). The grant is
    still capped by the budget left for the whole file; once that is gone the rest get UNKNOWN
    `budget_exhausted` (2.18, "targets the queue never reached"). This is the same carry the offline
    replay in `experiments/metrics.py` applies, so measured M1 and simulated Recall(tau) agree.

    `skipped_confirmed`: once a (class, node) is CONFIRMED, the same node reached from another entry
    point is not re-analysed -- it is already confirmed, and its B_t rolls into the bank. REFUTED
    does not skip: a refutation from one entry point says nothing about another.

    M2 issues no verdict at all: every target stays a static warning, UNKNOWN `static_only`.

    `static_elapsed` is the time the static stage already took, so `time_to_verdict` is measured from
    the start of the contract analysis as chapter 2.3 (Recall(tau)) requires.
    """
    run = runner or _run_target
    owner = {id(target): analysis for analysis, target in pairs}
    targets = [target for _, target in pairs]
    queue = _queue(targets, config)
    allocation = budgets(queue, config)
    budget = config.budget if budget is None else budget

    results: list[TargetResult] = []
    confirmed_nodes: set = set()
    spent = 0.0
    bank = 0.0  # B_t of earlier targets that finished early, carried forward along the queue

    for target in queue:
        base = allocation[id(target)]
        r, p = risk(target, config), priority(target, config)

        if not config.symbolic_execution:  # M2: static stage only
            results.append(_result(target, Verdict.UNKNOWN, r, p, base, 0.0,
                                    static_elapsed, UnknownReason.STATIC_ONLY))
            continue

        remaining = budget - spent
        if remaining <= 0.0:  # the whole-file budget is spent, the queue never reached this target
            results.append(_result(target, Verdict.UNKNOWN, r, p, base, 0.0,
                                    static_elapsed + spent, UnknownReason.BUDGET_EXHAUSTED))
            continue

        if target.node_key in confirmed_nodes:  # same node already confirmed elsewhere
            bank += base  # its unused budget rolls forward to the targets behind it
            results.append(_result(target, Verdict.UNKNOWN, r, p, base, 0.0,
                                   static_elapsed + spent, UnknownReason.SKIPPED_CONFIRMED))
            continue

        granted = min(base + bank, remaining)
        outcome, elapsed = run(owner[id(target)], target, config, granted)
        spent += elapsed
        bank = max(0.0, bank + base - elapsed)  # grew if it finished early, shrank if it dipped in
        if outcome.verdict is Verdict.CONFIRMED:
            confirmed_nodes.add(target.node_key)
        results.append(_result(target, outcome.verdict, r, p, base, elapsed,
                               static_elapsed + spent, outcome.reason, outcome.counterexample))
    return results


def _result(target, verdict, r, p, budget, elapsed, time_to_verdict, reason=None, cex=None):
    return TargetResult(
        target=target,
        verdict=verdict,
        risk=r,
        priority=p,
        budget=budget,
        elapsed=elapsed,
        time_to_verdict=time_to_verdict,
        reason=reason,
        counterexample=cex,
    )


def _search(
    machine: Machine,
    environment,
    controlled: tuple,
    analysis: "Analysis",
    target: "Target",
    config: Config,
    budget: float,
    expansion: "Expansion",
    target_set: set,
    nstar: set,
    distances: dict,
    initial: SymState,
    reach_only: bool = False,
) -> Outcome:
    """The worklist loop. Returns as soon as a path confirms; otherwise combines what it saw.

    `reach_only` is the re-entry model's directed reachability (phi_RE stage 2): the target is a
    vertex rather than an operation, and reaching it under a satisfiable PC is the whole question, so
    the class predicate is replaced by the bare `exists X: PC` check of `_reachability`.
    """
    start = time.monotonic()
    frontier: list[tuple["Vertex", SymState, dict, tuple]] = [(expansion.root, initial, {}, ())]
    pending: Optional[Outcome] = None  # the strongest non-CONFIRMED outcome seen so far

    while frontier:
        elapsed = time.monotonic() - start
        if elapsed > budget:
            return Outcome(Verdict.UNKNOWN, UnknownReason.TIMEOUT)
        vertex, state, visits, saves = _take(frontier, config, distances)

        if config.prune_outside_nstar and vertex not in nstar:
            continue  # this branch cannot reach the target, so the solver is never troubled

        node = expansion.node(vertex)
        if vertex in target_set and (reach_only or _covers(node, vertex.resume, target.point.op_index)):
            probe = Probe(machine, environment, target.entry_point, config, budget - elapsed, controlled)
            if reach_only:
                outcome = _reachability(probe, state)
            else:
                outcome = _evaluate(machine, probe, state, target, node, vertex.resume, analysis)
            if outcome.verdict is Verdict.CONFIRMED:
                return outcome
            pending = _stronger(pending, outcome)

        if _recursive_here(node, vertex):
            # The ICFG kept the ordinary edge for this call (recursion is not unrolled, 2.19), so
            # the recursive activation is not on the graph and cannot be modelled: abandon the path.
            pending = _stronger(pending, Outcome(Verdict.UNKNOWN, UnknownReason.RECURSION))
            continue

        # The operations after an inlined call depend on its result, so only the run up to the next
        # inlined call (`[resume, call)`) runs now; the rest runs when the node is re-entered after
        # the call returns (its `resume` vertex). A node with no further call runs to its end.
        call_index = _followed_index(node, vertex)
        try:
            _run_node(machine, state, node, call_index, start=vertex.resume)
        except UnsupportedConstruct:
            pending = _stronger(pending, Outcome(Verdict.UNKNOWN, UnknownReason.UNSUPPORTED_OP))
            continue  # the path is abandoned, not the whole target

        for successor, constraint in _branches(machine, state, expansion, vertex, node):
            if visits.get(successor, 0) >= config.k_unroll:
                continue  # loop bound k: a vertex is entered at most k_unroll times per path
            child = state.fork()
            if constraint is not None:
                child.pc.append(constraint)
            try:
                child_saves = _cross_frames(machine, child, expansion, vertex, node, successor, saves)
            except UnsupportedConstruct:
                pending = _stronger(pending, Outcome(Verdict.UNKNOWN, UnknownReason.UNSUPPORTED_OP))
                continue
            child_visits = dict(visits)
            child_visits[successor] = child_visits.get(successor, 0) + 1
            frontier.append((successor, child, child_visits, child_saves))

    if pending is not None:
        return pending
    return Outcome(Verdict.UNKNOWN, UnknownReason.BUDGET_EXHAUSTED)


def _take(frontier: list, config: Config, distances: dict):
    """Next item: nearest-to-target outside M3, last-in (DFS) inside it."""
    if config.distance_guided:
        index = min(
            range(len(frontier)),
            key=lambda i: distances.get(frontier[i][0], _INFINITY),
        )
        return frontier.pop(index)
    return frontier.pop()


def _recursive_here(node: Node, vertex: "Vertex") -> bool:
    """True if the next inlined call at this vertex targets a function already on the stack (2.19)."""
    found = next_inlined_call(node, vertex.resume)
    if found is None:
        return False
    _, callee = found
    return callee.canonical_name in {frame.callee_key for frame in vertex.stack}


def _followed_index(node: Node, vertex: "Vertex") -> Optional[int]:
    """Index of the inlined call the ICFG follows at this vertex, or None.

    It mirrors `Expansion._transfer`: the first inlined call at or after `resume` that is not already
    on the stack (a recursive one keeps its ordinary edge and is handled by `_recursive_here`).
    """
    found = next_inlined_call(node, vertex.resume)
    if found is None:
        return None
    index, callee = found
    if callee.canonical_name in {frame.callee_key for frame in vertex.stack}:
        return None
    return index


def _covers(node: Node, resume: int, op_index: int) -> bool:
    """True if `op_index` lies in this vertex's run `[resume, next inlined call or end)`.

    A node may be entered at several `resume` positions when it holds a chain of inlined calls; the
    predicate must be evaluated at the one whose run contains the target operation, so the state it
    sees is neither missing the preceding operations nor past a call whose result is not yet bound.
    """
    if op_index < resume:
        return False
    found = next_inlined_call(node, resume)
    end = found[0] if found is not None else len(node.irs)
    return op_index < end


def _cross_frames(
    machine: Machine,
    child: SymState,
    expansion: "Expansion",
    vertex: "Vertex",
    node: Node,
    successor: "Vertex",
    saves: tuple,
) -> tuple:
    """Keep the per-path call-frame stack in step with the successor's ICFG stack.

    A call edge (one frame deeper) snapshots rho and binds the arguments; a return edge (frames
    popped) restores the snapshot and binds the result to the call's lvalue. Modifier and placeholder
    frames do not carry values, so only internal-call frames (the ones that count towards depth) are
    tracked here. Every other edge leaves the stack untouched.
    """
    depth, successor_depth = len(vertex.stack), len(successor.stack)
    if successor_depth == depth + 1:
        frame = successor.stack[-1]
        if not frame.counts_towards_depth:
            return saves  # a modifier or `_` body: inlined control flow, no value frame
        index = _followed_index(node, vertex)
        ir = node.irs[index]
        snapshot = dict(child.rho)  # taken after `[resume, index)` ran, before the arguments are bound
        point = ProgramPoint(node.function, node, index)
        parameters = getattr(ir.function, "parameters", None) or []
        for parameter, argument in zip(parameters, ir.arguments):
            child.rho[parameter.name] = value_of(machine, child, point, argument)
        return saves + (_Save(frame, snapshot, ir.function, node, index),)
    if successor_depth < depth:
        removed = set(vertex.stack[successor_depth:])
        while saves and saves[-1].frame in removed:
            save = saves[-1]
            result = child.rho.get(return_slot(save.callee))
            child.rho = save.rho
            lvalue = save.site.irs[save.index].lvalue
            if lvalue is not None and result is not None:
                child.rho[lvalue.name] = result
            # The operations after the call run when the caller node is re-entered at `index + 1`
            # (the successor's `resume`), so they are not run here -- that is what lets a chained
            # call bind its predecessor's result before its own arguments are read.
            saves = saves[:-1]
        return saves
    return saves


def _evaluate(
    machine: Machine,
    probe: Probe,
    state: SymState,
    target: "Target",
    node: Node,
    resume: int,
    analysis: "Analysis",
) -> Outcome:
    """Run the node up to the target operation on a fork, then apply the class predicate.

    The predicate sees the state just before the target operation, which is what the operations
    `[resume, op_index)` of the node produce -- the `Index` that forms a reference, say, must have run
    so that the operand of the overflow can be read. `resume` is the vertex's entry index, so when the
    target follows an inlined call in the same node the already-run prefix is not run a second time.
    """
    fork = state.fork()
    point = target.point
    try:
        for index in range(resume, point.op_index):
            _step(machine, fork, ProgramPoint(node.function, node, index), node.irs[index])
    except UnsupportedConstruct:
        return Outcome(Verdict.UNKNOWN, UnknownReason.UNSUPPORTED_OP)

    cls = target.vuln_class
    try:
        if cls is VulnClass.OV:
            return check_overflow(probe, fork, point, node.irs[point.op_index])
        if cls is VulnClass.AC:
            return check_access(probe, fork)
        if cls is VulnClass.TO:
            return check_tx_origin(probe, fork)
        if cls is VulnClass.DC:
            return check_delegatecall(probe, fork, point, node.irs[point.op_index])
        if cls is VulnClass.UC:
            return check_unchecked(probe, fork)
        if cls is VulnClass.RE:
            return check_reentrancy(probe, fork, target, node, analysis)
    except UnsupportedConstruct:
        return Outcome(Verdict.UNKNOWN, UnknownReason.UNSUPPORTED_OP)
    raise NotImplementedError(f"no predicate for {cls}")


def _branches(
    machine: Machine, state: SymState, expansion: "Expansion", vertex: "Vertex", node: Node
) -> Iterator[tuple["Vertex", Optional[z3.BoolRef]]]:
    """The successors of a vertex, each with the condition the engine adds to PC to take it.

    For an IF / IFLOOP the condition is the branch term from `condition_of`: the true successor
    carries it, the false one its negation. Every other node yields its successors unconstrained.
    """
    successors = expansion.successors(vertex)
    if node.type in (NodeType.IF, NodeType.IFLOOP):
        term = condition_of(machine, state, node)
        true_key = _son_key(node.son_true)
        for successor in successors:
            yield successor, (term if successor.node_key == true_key else z3.Not(term))
        return
    for successor in successors:
        yield successor, None


def _son_key(node: Optional[Node]) -> Optional[tuple[str, int]]:
    if node is None:
        return None
    return (node.function.canonical_name, node.node_id)


def _run_node(
    machine: Machine, state: SymState, node: Node, upto: Optional[int] = None, start: int = 0
) -> None:
    """Apply the operations `node.irs[start:upto]`, skipping any interprocedural call.

    The bounds let the caller split a node at the one call the ICFG inlined: `[start, upto)` is the
    prefix before the call on the way in, and `[index + 1, end)` the suffix after it on the way back.
    """
    stop = len(node.irs) if upto is None else upto
    for index in range(start, stop):
        _step(machine, state, ProgramPoint(node.function, node, index), node.irs[index])


def _step(machine: Machine, state: SymState, point: ProgramPoint, ir) -> None:
    """One IR. An inlined call is not translated here: the ICFG routes control into the callee as its
    own vertices, and the engine binds the arguments and propagates the result at the call and return
    edges (`_cross_frames`). Translating it in place would double-run the body. This covers every
    internal call and any internal library call; a public/external library call falls through to the
    translator, which gives it an opaque result.
    """
    if isinstance(ir, InternalCall) or inlined_callee(ir) is not None:
        return
    execute(machine, state, point, ir)


def _stronger(current: Optional[Outcome], candidate: Outcome) -> Outcome:
    """Keep the more informative of two non-CONFIRMED outcomes.

    UNKNOWN outweighs REFUTED: a single path the engine could not settle means the target is not
    proven safe, so it must not be reported REFUTED. Among UNKNOWNs the first reason is kept.
    """
    if current is None:
        return candidate
    if current.verdict is Verdict.UNKNOWN:
        return current
    if candidate.verdict is Verdict.UNKNOWN:
        return candidate
    return current
