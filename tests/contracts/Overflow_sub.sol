// OV fixture, classic underflow. Compile with solc 0.4.24: all arithmetic is unchecked.
// Expected targets: ONE -- the subtraction `balances[msg.sender] -= amount`, unguarded.
//   E_t = {balances[msg.sender], amount} -> A = 1/2 = 0.5 (amount is an argument, the balance is
//         storage and is not controlled by value)
//   D = 1 (no V_auth, no lock), M = 1 (ether is transferred)
//   R = 0.8 * (0.4*0.5 + 0.4*1.0 + 0.2*1.0) = 0.64
//   b = 0 (no conditional node dominates the subtraction)
//   P = 0.640
// Verdict CONFIRMED and it must come from the STRONG condition: for every balance below 2^255
// the attacker picks amount = balance + 1. Counterexample is produced by fixing storage to 0.
pragma solidity 0.4.24;

contract OverflowSub {
    mapping(address => uint256) public balances;

    function withdrawAll(uint256 amount) public {
        balances[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }
}
