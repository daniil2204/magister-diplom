/*
 * Fixed version of smartbugs-curated arithmetic/timelock.sol
 * (pair, fix style: safemath).
 * Fix: the unchecked `lockTime[msg.sender] += _secondsToIncrease` is routed through a SafeMath-like
 * `add` whose body guards the sum with `require(c >= a)`. The internal library call is inlined (JUMP,
 * not DELEGATECALL). As with every pre-0.8 addition guard, the sum stays a storage-dependent target
 * (at lockTime == 0 no increment overflows, so the strong condition fails), hence the SC09 unit is
 * UNKNOWN `storage_dependent`, never CONFIRMED. Only the SC09 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://github.com/sigp/solidity-security-blog
 * @author: -
 * @vulnerable_at_lines: 22
 */

//added pragma version
 pragma solidity ^0.4.10;

 library SafeMath {
     function add(uint256 a, uint256 b) internal pure returns (uint256) {
         uint256 c = a + b;
         require(c >= a);
         return c;
     }
 }

 contract TimeLock {
     using SafeMath for uint256;

     mapping(address => uint) public balances;
     mapping(address => uint) public lockTime;

     function deposit() public payable {
         balances[msg.sender] += msg.value;
         lockTime[msg.sender] = now + 1 weeks;
     }

     function increaseLockTime(uint _secondsToIncrease) public {
         // <yes> <report> ARITHMETIC
         lockTime[msg.sender] = lockTime[msg.sender].add(_secondsToIncrease);
     }

     function withdraw() public {
         require(balances[msg.sender] > 0);
         require(now > lockTime[msg.sender]);
         uint transferValue = balances[msg.sender];
         balances[msg.sender] = 0;
         msg.sender.transfer(transferValue);
     }
 }
