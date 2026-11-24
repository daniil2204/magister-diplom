/*
 * Fixed version of smartbugs-curated access_control/incorrect_constructor_name2.sol
 * (pair, fix style: modifier).
 * Fix: the misnamed-constructor function missing (which lets anyone take ownership) is guarded by the
 * onlyowner modifier, so under the attacker model (sender != owner) the privileged write is
 * unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-118#incorrect-constructor-name1sol
 * @author: Ben Perez
 * @vulnerable_at_lines: 18
 */


pragma solidity ^0.4.24;

contract Missing{
    address private owner;

    modifier onlyowner {
        require(msg.sender==owner);
        _;
    }
    // <yes> <report> ACCESS_CONTROL
    function missing()
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
