// SC09 fixture where the loop bound k decides the verdict. Compile with solc 0.4.24 (all
// arithmetic unchecked below 0.8).
//
// The accumulator starts at zero, so the FIRST visit to `acc += step` computes 0 + step, which
// cannot overflow for any step. The SECOND visit computes step + step, which overflows for every
// step >= 2^255. So the operation is unreachable-as-a-bug with one unrolling and reachable with
// two, and the fixture measures k instead of merely exercising it:
//
//     k = 1 -> REFUTED   (every path in Pi_t^{<=1} that reaches the operation has acc = 0,
//                         and Ovf_+(0, step) = ULT(0 + step, 0) is false for every step)
//     k = 2 -> CONFIRMED (the two-iteration path has acc = step, so Ovf_+(step, step) =
//                         ULT(step + step, step) is satisfiable; the weak condition is sat and
//                         the strong one is sat too, because the formula contains no storage
//                         term at all -- acc is a local and step is a parameter, so the
//                         universal quantifier over X_sto in D is vacuous)
//     counterexample at k = 2: n = 2, step = 2^255
//
// The bound is the parameter `n` and not an array length on purpose: an array length would make
// the number of iterations a storage value, and the verdict would then depend on the storage
// abstraction rather than on k.
//
// Expected targets: exactly ONE SC09 target -- `acc += step`.
//
//   The loop counter `i++` is NOT a target, and this is the fixture that checks it: the static
//   rule requires an operand that depends BY VALUE on X_env or X_arg, and `i` depends only on
//   the literals 0 and 1. That `i` is compared with the parameter `n` is a control dependency,
//   not a data one. (The result of `i++` does reach a sink -- the loop condition -- so it is the
//   first condition of the SC09 rule, not the second, that rules it out.)
//
//   acc += step:
//     E_t = {x, y} = {acc, step}; step is in X_arg, and acc depends on step through
//           `acc = acc + step`, so both are controlled -> A = 2/2 = 1.0
//     V_auth = {}, no lock variable: g = 0 -> D = 1.0
//     M = 0.5 -- the entry point transfers no ether, and `total` is a plain uint256, not a
//               mapping(address => uint)
//     S(OV) = 0.8
//     R = 0.8 * (0.4*1.0 + 0.4*1.0 + 0.2*0.5) = 0.8 * 0.9 = 0.72
//     b = 1 (the IFLOOP node of the for-loop; there is no require) -> P = 0.72 * 2^(-0.5) ~= 0.5091
pragma solidity 0.4.24;

contract OverflowLoop {
    uint256 public total;

    function accumulate(uint256 n, uint256 step) public {
        uint256 acc = 0;
        for (uint256 i = 0; i < n; i++) {
            acc += step;
        }
        total = acc;
    }
}
