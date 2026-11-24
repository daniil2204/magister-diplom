/*
 * Fixed version of smartbugs-curated arithmetic/integer_overflow_minimal.sol
 * (pair, fix style: require).
 * Fix: the unchecked `count -= input` is guarded by `require(count >= input)`, which contradicts the
 * subtraction-underflow predicate on every path, so the SC09 target is refuted. Only the SC09 unit is
 * scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/integer_overflow_and_underflow/integer_overflow_minimal.sol
 * @author: -
 * @vulnerable_at_lines: 17
 */

//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.19;

contract IntegerOverflowMinimal {
    uint public count = 1;

    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        require(count >= input);
        count -= input;
    }
}
