// OV fixture, ERC20-style transfer guarded by a balance check.
// Compile with solc 0.4.24: all arithmetic is unchecked.
// Expected targets: TWO, both with S(OV) = 0.8, A = 1/2 = 0.5 (v is an argument, the balances are
// storage), D = 1, M = 1, R = 0.64, b = 1 (the require) -> P ~= 0.4525.
//   1) `balances[msg.sender] -= v`  REFUTED -- the require makes underflow unsat.
//   2) `balances[to] += v`          UNKNOWN storage_dependent -- inside D both operands are below
//      2^255, so their sum is at most 2^256 - 2 and cannot wrap; outside D it can. The weak
//      condition is sat, the strong one is not.
// Evaluation unit (OV, transfer) = UNKNOWN: positive in moderate mode, negative in strict mode.
pragma solidity 0.4.24;

contract OverflowTransfer {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 v) public {
        require(balances[msg.sender] >= v);
        balances[msg.sender] -= v;
        balances[to] += v;
    }
}
