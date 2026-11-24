// OV fixture, unit-level NEGATIVE. Compile with solc 0.4.24: all arithmetic is unchecked.
// Expected targets: ONE -- the subtraction, fully guarded by the require.
//   E_t = {balances[msg.sender], v} -> A = 1/2 = 0.5
//   D = 1 (no V_auth, no lock), M = 1 (mapping(address => uint) is written)
//   R = 0.8 * (0.4*0.5 + 0.4*1.0 + 0.2*1.0) = 0.64
//   b = 1 (the require) -> P ~= 0.4525
// Verdict REFUTED, so the evaluation unit (OV, burn) is negative in BOTH strict and moderate
// mode. This is the only OV fixture that is a clean negative at unit level -- Overflow_transfer
// is not, because its addition is UNKNOWN.
pragma solidity 0.4.24;

contract OverflowGuarded {
    mapping(address => uint256) public balances;

    function burn(uint256 v) public {
        require(balances[msg.sender] >= v);
        balances[msg.sender] -= v;
    }
}
