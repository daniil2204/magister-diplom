/*
 * @source: http://blockchain.unica.it/projects/ethereum-survey/attacks.html#simpledao
 * @author: -
 * @vulnerable_at_lines: 19
 */

pragma solidity ^0.4.2;

contract SimpleDAO {
  mapping (address => uint) public credit;

  function donate(address to) payable {
    credit[to] += msg.value;
  }

  function withdraw(uint amount) {
    if (credit[msg.sender]>= amount) {
      // <yes> <report> REENTRANCY
      bool res = msg.sender.call.value(amount)();
      credit[msg.sender]-=amount;
    }
  }

  function queryCredit(address to) returns (uint){
    return credit[to];
  }
}

// Everything above this line is the file dataset/reentrancy/simple_dao.sol of smartbugs-curated
// at commit 230e6491, copied character for character (only the CRLF line endings became LF, to
// match the rest of the repository). The line numbers therefore match the dataset labels: line 19
// is the one marked REENTRANCY, which is why the control comment is appended and not prepended.
// Tests pin solc 0.4.24 (the highest 0.4.x installed; the pragma is ^0.4.2). Below 0.8 ALL
// arithmetic is unchecked.
//
// Reentrancy_if.sol is the same contract ported to 0.8 with queryCredit dropped. This one shows
// what the method does on the real dataset sample, and it is the fixture that exercises the
// bound msg.value < 2^128.
//
// Expected targets: FOUR. V_auth is empty and there is no require anywhere, so g = 0 and D = 1.0
// for all of them; every entry point either writes mapping(address => uint) or sends ether, so
// M = 1 for all of them too. b = 0 in donate and b = 1 in withdraw (the IF; `if` is the only
// branching construct in the contract).
//
//   donate -- OV on `credit[to] += msg.value`.
//     E_t = {x, y} = {credit[to], msg.value}: storage is not controlled, msg.value is -> A = 0.5
//     R = 0.8 * (0.4*0.5 + 0.4*1.0 + 0.2*1.0) = 0.64, b = 0 -> P = 0.64
//     UNKNOWN `storage_dependent`. The weak condition is satisfiable (credit[to] is free), but
//     the strong one is not: over D every credit[to] is below 2^255 and msg.value is below 2^128,
//     so the sum cannot wrap. WITHOUT the bound on msg.value this target would be CONFIRMED --
//     and that would be a false positive produced by the model alone, because no attacker can
//     send 2^255 wei. This is the fixture that fixes that.
//
//   withdraw -- OV on `credit[msg.sender] -= amount`.
//     E_t = {credit[msg.sender], amount} -> A = 0.5
//     R = 0.64, b = 1 -> P = 0.64 * 2^(-0.5) ~= 0.4525
//     REFUTED: the IF puts credit[msg.sender] >= amount into PC on this path.
//
//   withdraw -- RE on the same write, which follows the call.
//     E_t = {call address, value} = {msg.sender, amount}: both controlled -> A = 1.0
//     R = 1.0 * (0.4 + 0.4 + 0.2) = 1.0, b = 1 -> P ~= 0.7071
//     CONFIRMED. `credit` is read before the call and written after it, and `call` forwards all
//     the gas.
//
//   withdraw -- UC on the same write: `res` is assigned and never read by a branching node.
//     E_t = {call address, call arguments} = {msg.sender}: `call.value(amount)()` passes no
//           arguments at all -> A = 1.0. The 0.8 spelling `call{value: amount}("")` writes the
//           empty calldata as a literal argument, so Reentrancy_if gets A = 0.5 for the same
//           call. The difference is syntactic and is reported as such.
//     R = 0.6 * 1.0 = 0.6, b = 1 -> P = 0.6 * 2^(-0.5) ~= 0.4243
//     CONFIRMED.
//
//   queryCredit -- ZERO targets: it reads storage and does no arithmetic.
//
// SmartBugs labels this contract for reentrancy only, so the UC target counts as a false positive
// by the labels even though the result really is unchecked. That is the label-incompleteness case
// chapter 3 reports under the corrected precision.
