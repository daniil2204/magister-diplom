/*
 * Fixed version of smartbugs-curated arithmetic/integer_overflow_mul.sol
 * (pair, fix style: safemath).
 * Fix: the unchecked `count *= input` is routed through a SafeMath-like `mul` whose body guards the
 * product with `require(a == 0 || c / a == b)`. The internal library call is inlined (JUMP, not
 * DELEGATECALL) so the engine evaluates the guard exactly. The multiplication stays a storage-dependent
 * target (at count == 0 no input overflows, so the strong condition fails), hence the SC09 unit is
 * UNKNOWN `storage_dependent`, never CONFIRMED. Only the SC09 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/integer_overflow_and_underflow/integer_overflow_mul.sol
 * @author: -
 * @vulnerable_at_lines: 17
 */

//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.19;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        require(a == 0 || c / a == b);
        return c;
    }
}

contract IntegerOverflowMul {
    using SafeMath for uint256;
    uint public count = 2;

    function run(uint256 input) public {
        // <yes> <report> ARITHMETIC
        count = count.mul(input);
    }
}
