// Minimal SC01 fixture (access control). Compile with solc 0.8.x (tests pin 0.8.20).
// `owner` is compared with msg.sender in onlyOwner, so V_auth = {owner}.
// Priv operations here: the write to owner, and selfdestruct.
//
// Expected targets: TWO AC targets. No TO target (no condition reads tx.origin).
//
//   setOwner: ONE AC target -- the write `owner = n`, unguarded.
//     E_t = {sender, operands of the priv op} = {msg.sender, n}, both controlled -> A = 1.0
//     g = 0 -> D = 1.0
//     M = 0.5 -- the entry point neither transfers ether nor writes mapping(address => uint)
//     R = 1.0 * (0.4*1.0 + 0.4*1.0 + 0.2*0.5) = 0.4 + 0.4 + 0.1 = 0.90
//     b = 0 -> P = 0.90
//     CONFIRMED: any a* reaches the write.
//
//   kill: ONE AC target -- the selfdestruct.
//     E_t = {msg.sender, owner} -- the recipient is a state variable, not controlled -> A = 0.5
//     g = 1 (require(msg.sender == owner) dominates it) -> D = 0.5
//     M = 1.0 -- selfdestruct forwards the entire remaining balance, which is a movement of
//               value in the sense M_t is about, even though it is not a call.
//     R = 1.0 * (0.4*0.5 + 0.4*0.5 + 0.2*1.0) = 0.2 + 0.2 + 0.2 = 0.60
//     b = 1 (the require inside the modifier) -> P = 0.60 * 2^(-0.5) ~= 0.424
//     REFUTED: under the attacker model sender != owner.
pragma solidity ^0.8.0;

contract AccessUnprotected {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address n) public {
        owner = n;
    }

    function kill() public onlyOwner {
        selfdestruct(payable(owner));
    }
}
