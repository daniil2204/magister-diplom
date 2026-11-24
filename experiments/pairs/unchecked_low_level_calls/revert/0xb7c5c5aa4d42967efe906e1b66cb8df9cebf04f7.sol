/*
 * Fixed version of smartbugs-curated unchecked_low_level_calls/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol
 * (pair, fix style: revert).
 * Fix: the low-level call in withdraw is guarded by `if (!call) revert();`, so the success flag is
 * checked and a failed call reverts instead of being ignored. Only the SC06 unit is scored here (the
 * pre-0.8 reentrancy write that remains is not a pair false positive).
 * solc version inherited from the original (0.4.x).
 *
 * @source: etherscan.io
 * @author: -
 * @vulnerable_at_lines: 25
 */

pragma solidity ^0.4.23;

/*
!!! THIS CONTRACT IS EXPLOITABLE AND FOR EDUCATIONAL PURPOSES ONLY !!!

This smart contract allows a user to (insecurely) store funds
in this smart contract and withdraw them at any later point in time
*/

contract keepMyEther {
    mapping(address => uint256) public balances;
    
    function () payable public {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        // <yes> <report> UNCHECKED_LL_CALLS
        if (!msg.sender.call.value(balances[msg.sender])()) revert();
        balances[msg.sender] = 0;
    }
}