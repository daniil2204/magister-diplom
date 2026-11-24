/*
 * Fixed version of smartbugs-curated arithmetic/integer_overflow_add.sol
 * (pair, fix style: require).
 * Fix: the unchecked `count += input` is guarded by `require(count + input >= count)`, which
 * contradicts the addition-overflow predicate on every path, so the SC09 target is refuted. Only the
 * SC09 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite/blob/master/benchmarks/integer_overflow_add.sol
 * @author: -
 * @vulnerable_at_lines: 17
 */

//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.19;

contract IntegerOverflowAdd {
    uint public count = 1;

    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        require(count + input >= count);
        count += input;
    }
}
