// Fixture for addmod and mulmod (table 2.1). Compile with solc 0.8.x (tests pin 0.8.20).
//
// Expected targets: ZERO, in both functions. addmod and mulmod are SolidityCall and not Binary,
// so the SC09 rule never looks at them -- and it should not: both are defined over the integers
// and reduced only afterwards, so neither can overflow. That is also why `_do_modular` computes
// them in double width instead of leaving them uninterpreted: `addmod(2^255, 2^255, 7)` is 2,
// while the 256-bit sum wraps to 0 and would give 0.
//
// k = 0 reverts, so the path condition gains k != 0 exactly as it does for `/` and `%`.
pragma solidity ^0.8.0;

contract Modular {
    function addRing(uint256 x, uint256 y, uint256 k) external pure returns (uint256) {
        return addmod(x, y, k);
    }

    function mulRing(uint256 x, uint256 y, uint256 k) external pure returns (uint256) {
        return mulmod(x, y, k);
    }
}
