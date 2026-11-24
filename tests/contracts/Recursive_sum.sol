// OV fixture for RECURSION. Compile with solc 0.4.24 (all arithmetic unchecked). `rec` calls
// itself, which the ICFG does not unroll (2.19): it keeps the ordinary edge, so the recursive
// activation is off the graph and the engine cannot model it.
//   run target: `s + 1`, where s = rec(n, 0). The base-case path (n == 0) returns 0, so s + 1 = 1
//     never overflows -> that path is REFUTED. The path through the self-call reaches a call to a
//     function already on the stack -> UNKNOWN `recursion`. UNKNOWN outweighs REFUTED, so the target
//     is UNKNOWN with reason recursion -- not a silent REFUTED that would hide the recursion.
// Control numbers (rec is inlined once from run, so the one `if (n == 0)` gives b = 1 everywhere):
//   run target `s + 1`: A = 0.5 (s controlled, 1 is a literal), D = 1, M = 1 -> R = 0.64, P = 0.4525.
//   rec `n - 1` (feeds the call argument, a sink): A = 0.5 -> R = 0.64, P = 0.4525.
//   rec `acc + n` (both parameters): A = 1 -> R = 0.8, P = 0.5657.
pragma solidity 0.4.24;

contract RecursiveSum {
    mapping(address => uint256) public balances;

    function rec(uint256 n, uint256 acc) internal returns (uint256) {
        if (n == 0) {
            return acc;
        }
        return rec(n - 1, acc + n);
    }

    function run(uint256 n) public {
        uint256 s = rec(n, 0);
        balances[msg.sender] = s + 1;
    }
}
