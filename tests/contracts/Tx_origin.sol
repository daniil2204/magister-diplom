// Minimal SC01 fixture (tx.origin authentication). Compile with solc 0.8.x (tests pin 0.8.20).
// V_auth = {owner}: owner is compared with msg.sender in onlyOwner.
//
// Expected targets: THREE -- two on the tx.origin-guarded write (AC and TO), one on the
// msg.sender-guarded write (AC only). AC and TO are separate predicates (2.8) and (2.9) but the
// same SWC class, so setOwnerOrigin is ONE evaluation unit (SC01, setOwnerOrigin).
//
//   setOwnerOrigin, write `owner = n`:
//     g = 0. require(tx.origin == owner) is NOT a guard: g counts comparisons of msg.sender with
//     a V_auth variable, and tx.origin is not msg.sender. That is the whole point of the class.
//     b = 1 (the require) in both targets, M = 0.5 (no ether, no mapping(address => uint)).
//
//     AC target: E_t = {msg.sender, n}, both controlled -> A = 1.0, D = 1.0
//       R = 1.0 * (0.4*1.0 + 0.4*1.0 + 0.2*0.5) = 0.90
//       P = 0.90 * 2^(-0.5) ~= 0.636
//       CONFIRMED: origin is unconstrained, so origin = owner satisfies the require while
//       sender = a*.
//
//     TO target: E_t = {sender, origin}, both in X_env -> A = 1.0 (always, for every TO target),
//       D = 1.0
//       R = 0.90, P ~= 0.636
//       CONFIRMED.
//
//   setOwnerSender, write `owner = n`: ONE AC target, ZERO TO targets -- this is the negative
//     case for phi_TO (2.9): no path condition reads tx.origin.
//     E_t = {msg.sender, n} -> A = 1.0; g = 1 -> D = 0.5; M = 0.5
//     R = 1.0 * (0.4*1.0 + 0.4*0.5 + 0.2*0.5) = 0.4 + 0.2 + 0.1 = 0.70
//     b = 1 -> P = 0.70 * 2^(-0.5) ~= 0.495
//     REFUTED: under the attacker model sender != owner.
pragma solidity ^0.8.0;

contract TxOrigin {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setOwnerOrigin(address n) public {
        require(tx.origin == owner);
        owner = n;
    }

    function setOwnerSender(address n) public onlyOwner {
        owner = n;
    }
}
