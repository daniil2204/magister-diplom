/*
 * Fixed version of smartbugs-curated access_control/simple_suicide.sol
 * (pair, fix style: require).
 * Fix: the unprotected selfdestruct is guarded by `require(msg.sender == owner)` in the body (owner is
 * a state variable compared with the sender, so it enters V_auth); under the attacker model
 * (sender != owner) the selfdestruct is unreachable and the SC01 target is refuted. Only the SC01 unit
 * is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/unprotected_critical_functions/simple_suicide.sol
 * @author: -
 * @vulnerable_at_lines: 12,13
 */

//added prgma version
pragma solidity ^0.4.0;

contract SimpleSuicide {
  address owner;
  // <yes> <report> ACCESS_CONTROL
  function sudicideAnyone() {
    require(msg.sender == owner);
    selfdestruct(msg.sender);
  }

}
