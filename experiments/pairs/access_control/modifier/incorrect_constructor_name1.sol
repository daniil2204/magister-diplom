/*
 * Fixed version of smartbugs-curated access_control/incorrect_constructor_name1.sol
 * (pair, fix style: modifier).
 * Fix: the misnamed-constructor function IamMissing (which lets anyone take ownership) is guarded by
 * the onlyowner modifier, so under the attacker model (sender != owner) the privileged write is
 * unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/trailofbits/not-so-smart-contracts/blob/master/wrong_constructor_name/incorrect_constructor.sol
 * @author: Ben Perez
 * @vulnerable_at_lines: 20
 */

pragma solidity ^0.4.24;

contract Missing{
    address private owner;

    modifier onlyowner {
        require(msg.sender==owner);
        _;
    }

    // The name of the constructor should be Missing
    // Anyone can call the IamMissing once the contract is deployed
    // <yes> <report> ACCESS_CONTROL
    function IamMissing()
        public
        onlyowner
    {
        owner = msg.sender;
    }

    function () payable {}

    function withdraw()
        public
        onlyowner
    {
       owner.transfer(this.balance);
    }
}
