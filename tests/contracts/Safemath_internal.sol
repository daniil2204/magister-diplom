// OV fixture for internal-call RETURN propagation. Compile with solc 0.4.24 (all arithmetic
// unchecked). `store` reads the result of an internal call and overflows it, so the verdict depends
// on the engine carrying the callee's return value back into the caller's variable.
//   store target: `s + 1`, where s = addUnchecked(a, b) = a + b.
//   With return propagation: s is symbolic (a + b), so (a + b) + 1 overflows when a + b = 2^256-1
//     => CONFIRMED (the strong condition holds: storage is not involved).
//   Without it: s stays 0, s + 1 = 1 never overflows => REFUTED. This is the regression the
//     fixture guards against.
//   E_t = {s, 1} -> A = 1/2 = 0.5 (1 is a constant), D = 1 (no V_auth), M = 1 (mapping balances).
//   R = 0.8 * (0.4*0.5 + 0.4*1 + 0.2*1) = 0.64; b = 0; P = 0.640.
pragma solidity 0.4.24;

contract SafeMathInternal {
    mapping(address => uint256) public balances;

    function addUnchecked(uint256 a, uint256 b) internal returns (uint256) {
        return a + b;
    }

    function store(uint256 a, uint256 b) public {
        uint256 s = addUnchecked(a, b);
        balances[msg.sender] = s + 1;
    }
}
