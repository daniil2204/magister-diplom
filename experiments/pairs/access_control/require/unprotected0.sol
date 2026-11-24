/*
 * Fixed version of smartbugs-curated access_control/unprotected0.sol
 * (pair, fix style: require).
 * Fix: the unprotected changeOwner (which lets anyone overwrite the owner) checks
 * `require(msg.sender == owner)` in its body (owner is a state variable compared with the sender, so
 * it enters V_auth); under the attacker model (sender != owner) the privileged write is unreachable
 * and the SC01 target is refuted. Only the SC01 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/trailofbits/not-so-smart-contracts/blob/master/unprotected_function/Unprotected.sol
 * @author: -
 * @vulnerable_at_lines: 25
 */

 pragma solidity ^0.4.15;

 contract Unprotected{
     address private owner;

     modifier onlyowner {
         require(msg.sender==owner);
         _;
     }

     function Unprotected()
         public
     {
         owner = msg.sender;
     }

     // This function should be protected
     // <yes> <report> ACCESS_CONTROL
     function changeOwner(address _newOwner)
         public
     {
        require(msg.sender == owner);
        owner = _newOwner;
     }

    /*
    function changeOwner_fixed(address _newOwner)
         public
         onlyowner
     {
        owner = _newOwner;
     }
     */
 }
