// Constructor fixture. Compile with solc 0.8.x (tests pin 0.8.20).
// `owner` is compared with msg.sender in onlyOwner, so V_auth = {owner} and every write to owner
// is a privileged operation (Priv).
//
// Expected targets: ONE.
//   constructor: ZERO targets. `owner = msg.sender` is a write to a V_auth variable and therefore
//   Priv, and it can never be guarded -- without the constructor exclusion rule every contract in
//   the dataset would get a spurious SC01 CONFIRMED. This fixture is what catches that.
//
//   setOwner: ONE AC target (the write `owner = n`).
//     E_t = {sender, operands of the priv op} = {msg.sender, n}, both controlled -> A = 1
//     g = 1 (require(msg.sender == owner) dominates the write) -> D = 0.5
//     M = 0.5 -- the entry point neither transfers ether nor writes a mapping(address => uint);
//               it only writes the scalar `owner`. This is the only fixture with M = 0.5.
//     R = 1.0 * (0.4*1.0 + 0.4*0.5 + 0.2*0.5) = 0.4 + 0.2 + 0.1 = 0.70
//     b = 1 (the require inside the modifier) -> P = 0.70 * 2^(-0.5) ~= 0.495
//     REFUTED: under the attacker model sender != owner.
pragma solidity ^0.8.0;

contract OwnedCtor {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address n) public onlyOwner {
        owner = n;
    }
}
