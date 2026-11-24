// OV fixture, BEC-style batch transfer. Compile with solc 0.4.24: all arithmetic is unchecked.
// Expected targets: FOUR, all in batch2. S(OV) = 0.8, D = 1 (no V_auth, no lock),
// M = 1 (mapping(address => uint) is written), so every target has
//   A = 1/2 = 0.5 (one operand controlled by value, the other a literal or storage)
//   R = 0.8 * (0.4*0.5 + 0.4*1.0 + 0.2*1.0) = 0.8 * 0.8 = 0.64
//
//   1) `2 * _value`            b = 0 -> P = 0.640   CONFIRMED (storage not involved)
//   2) `balances[msg.sender] -= amount`  b = 1 -> P ~= 0.4525  REFUTED (guarded by the require)
//   3) `balances[a] += _value`           b = 1 -> P ~= 0.4525  UNKNOWN storage_dependent
//   4) `balances[b] += _value`           b = 1 -> P ~= 0.4525  UNKNOWN storage_dependent
//
// Targets 3 and 4 are storage_dependent: with all balances zero inside D no overflow is possible,
// but for balances[a] > 2^254 the wrap `amount = 2*_value` lets the require pass while the
// addition overflows. The weak condition is sat, the strong one is not.
// Evaluation unit (OV, batch2) = CONFIRMED.
pragma solidity 0.4.24;

contract OverflowMul {
    mapping(address => uint256) public balances;

    // No deposit() on purpose: under 0.4.24 `balances[msg.sender] += msg.value` would itself be
    // an OV target and break the expected target count.
    function batch2(address a, address b, uint256 _value) public {
        uint256 amount = 2 * _value;
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[a] += _value;
        balances[b] += _value;
    }
}
