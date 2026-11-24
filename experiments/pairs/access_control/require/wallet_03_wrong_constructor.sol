/*
 * Fixed version of smartbugs-curated access_control/wallet_03_wrong_constructor.sol
 * (pair, fix style: require).
 * Fix: the misnamed-constructor function initWallet (which lets anyone take over as creator) checks
 * `require(msg.sender == creator)` in its body (creator is a state variable compared with the sender,
 * so it enters V_auth); under the attacker model (sender != creator) the privileged write is
 * unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
 * solc version inherited from the original (0.4.x).
 *
 * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-105#wallet-03-wrong-constructorsol
 * @author: -
 * @vulnerable_at_lines: 19,20
 */

 pragma solidity ^0.4.24;

 /* User can add pay in and withdraw Ether.
    The constructor is wrongly named, so anyone can become 'creator' and withdraw all funds.
 */

 contract Wallet {
     address creator;

     mapping(address => uint256) balances;
     
     // <yes> <report> ACCESS_CONTROL
     function initWallet() public {
         require(msg.sender == creator);
         creator = msg.sender;
     }

     function deposit() public payable {
         assert(balances[msg.sender] + msg.value > balances[msg.sender]);
         balances[msg.sender] += msg.value;
     }

     function withdraw(uint256 amount) public {
         require(amount <= balances[msg.sender]);
         msg.sender.transfer(amount);
         balances[msg.sender] -= amount;
     }

     // In an emergency the owner can migrate  allfunds to a different address.

     function migrateTo(address to) public {
         require(creator == msg.sender);
         to.transfer(this.balance);
     }

 }
