// OV fixture with BOTH operands controlled, used to vary A and D for the sensitivity analysis
// and to test the attacker model for OV. Compile with solc 0.4.24: all arithmetic is unchecked.
// Expected targets: TWO, one per function.
//
//   mulArgs: E_t = {_a, _b}, both arguments -> A = 1
//            D = 1 (no guard), M = 1 (mapping(address => uint) is written)
//            R = 0.8 * (0.4*1.0 + 0.4*1.0 + 0.2*1.0) = 0.8
//            b = 0 -> P = 0.800
//            CONFIRMED (storage is not involved, the strong condition holds).
//
//   mulOwner: same expression, but onlyOwner.
//            A = 1, g = 1 -> D = 0.5, M = 1
//            R = 0.8 * (0.4*1.0 + 0.4*0.5 + 0.2*1.0) = 0.8 * 0.8 = 0.64
//            b = 1 (the require inside the modifier) -> P ~= 0.4525
//            REFUTED: under the attacker model sender != owner, so require(msg.sender == owner)
//            is already unsat on the WEAK condition. This is the attacker-model test for OV.
pragma solidity 0.4.24;

contract OverflowArgs {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function mulArgs(uint256 _a, uint256 _b) public {
        balances[msg.sender] = _a * _b;
    }

    function mulOwner(uint256 _a, uint256 _b) public onlyOwner {
        balances[msg.sender] = _a * _b;
    }
}
