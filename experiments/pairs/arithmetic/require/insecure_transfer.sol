/*
 * Fixed version of smartbugs-curated arithmetic/insecure_transfer.sol
 * (pair, fix style: require).
 * Fix: the unchecked credit `balanceOf[_to] += _value` is guarded by an explicit bounds check
 * `require(balanceOf[_to] + _value >= balanceOf[_to])`, which contradicts the addition-overflow
 * predicate on every path, so the SC09 target on the add is refuted. Only the SC09 unit is scored
 * here (the subtraction was already guarded by the existing balance require).
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://consensys.github.io/smart-contract-best-practices/known_attacks/#front-running-aka-transaction-ordering-dependence
 * @author: consensys
 * @vulnerable_at_lines: 18
 */

pragma solidity ^0.4.10;

contract IntegerOverflowAdd {
    mapping (address => uint256) public balanceOf;

    // INSECURE
    function transfer(address _to, uint256 _value) public{
        /* Check if sender has balance */
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        // <yes> <report> ARITHMETIC
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[_to] += _value;
}

}
