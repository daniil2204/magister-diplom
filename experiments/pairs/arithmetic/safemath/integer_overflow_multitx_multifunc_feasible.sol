/*
 * Fixed version of smartbugs-curated arithmetic/integer_overflow_multitx_multifunc_feasible.sol
 * (pair, fix style: safemath).
 * Fix: the unchecked `count -= input` is routed through a SafeMath-like `sub` whose body guards the
 * subtraction with `require(b <= a)`. The internal library call is inlined (JUMP, not DELEGATECALL),
 * so on every surviving path the guard contradicts the underflow predicate and the SC09 target is
 * refuted. Only the SC09 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
 * @author: Suhabe Bugrara
 * @vulnerable_at_lines: 25
 */

//Multi-transactional, multi-function
//Arithmetic instruction reachable

pragma solidity ^0.4.23;

library SafeMath {
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        return a - b;
    }
}

contract IntegerOverflowMultiTxMultiFuncFeasible {
    using SafeMath for uint256;
    uint256 private initialized = 0;
    uint256 public count = 1;

    function init() public {
        initialized = 1;
    }

    function run(uint256 input) {
        if (initialized == 0) {
            return;
        }
        // <yes> <report> ARITHMETIC
        count = count.sub(input);
    }
}
