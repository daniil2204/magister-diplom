// Entry-point fixture. Compile with solc 0.8.x (tests pin 0.8.20); the arithmetic is explicitly
// wrapped in `unchecked`, so it is an OV candidate even under 0.8.
//
// Expected targets: TWO OV targets, both with entry point `mint` and both in the body of
// `_mint`. The whole context is computed from the ENTRY POINT, so onlyOwner on mint() protects
// the otherwise unguarded _mint():
//     E_t = {x, y}; for `totalSupply += v` that is {totalSupply, v}, for `balances[to] += v`
//           that is {balances[to], v}. Only v is controlled by value -> A = 1/2 = 0.5
//     g = 1 (require(msg.sender == owner) in the entry point) -> D = 0.5
//     M = 1 (the entry point writes mapping(address => uint) balances)
//     R = 0.8 * (0.4*0.5 + 0.4*0.5 + 0.2*1.0) = 0.8 * 0.6 = 0.48
//     b = 1 (the require inside the modifier) -> P = 0.48 * 2^(-0.5) ~= 0.339
//     Both REFUTED: the weak condition is already unsat because the attacker cannot pass
//     onlyOwner. Evaluation unit (OV, _mint) = REFUTED.
//
// If _mint were analysed as an entry point in its own right the guard would be lost and the
// verdict would wrongly be CONFIRMED. That is the bug this fixture catches.
//
//   _burnDead: ZERO targets -- no public caller, so the node is unreachable and no target is
//   generated. Dead code is not a vulnerability.
//   constructor: ZERO targets.
pragma solidity ^0.8.0;

contract MintInternal {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 v) public onlyOwner {
        _mint(to, v);
    }

    function _mint(address to, uint256 v) internal {
        unchecked {
            totalSupply += v;
            balances[to] += v;
        }
    }

    function _burnDead(uint256 v) internal {
        unchecked {
            totalSupply -= v;
        }
    }
}
