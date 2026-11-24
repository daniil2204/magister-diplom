// SC08 + SC06 fixture with a real IF on the path to the target.
//
// Modelled on SimpleDAO from the `reentrancy` category of SmartBugs Curated; the original was
// downloaded and compared line by line. Two deliberate departures from it, both reported to the
// author before this file was written:
//
//   1. The original is `pragma solidity ^0.4.2`, where ALL arithmetic is unchecked. Ported to
//      0.8 so that the fixture carries exactly the two targets it is meant to isolate; under
//      0.4 it would also carry two SC09 targets (see the note at the bottom).
//   2. `queryCredit` is dropped: it is a view function and produces no target of any class.
//
// Everything that matters is kept: the guard is an `if`, not a `require`; the call result is
// ignored; the storage write happens after the call; and -- unlike Vault.sol -- the transferred
// amount comes from an ARGUMENT, not from storage. That last point is why A = 1 for RE here and
// A = 0.5 in Vault, which is what makes this fixture a check that the numbers are computed
// rather than copied.
//
// Expected targets: exactly TWO, both on the SAME node -- the write `credit[msg.sender] -= amount`
// after the call. The target is the write, not the call (see "RE and UC" in CLAUDE.md).
//
//   RE (SC08):
//     E_t = {call address, value} = {msg.sender, amount}; msg.sender is in X_env and amount is
//           in X_arg, so both are controlled -> A = 2/2 = 1.0
//     V_auth = {} and `credit` is a mapping, so it is not a lock variable: g = 0 -> D = 1.0
//     M = 1.0 (the entry point calls with value and writes mapping(address => uint))
//     S(RE) = 1.0
//     R = 1.0 * (0.4*1.0 + 0.4*1.0 + 0.2*1.0) = 0.4 + 0.4 + 0.2 = 1.00
//     b = 1 (the IF node; there is no require anywhere) -> P = 1.00 * 2^(-0.5) ~= 0.7071
//     CONFIRMED: the callee re-enters `withdraw` while `credit[msg.sender]` still holds the old
//     value, because the subtraction happens only after the call returns.
//
//   UC (SC06):
//     E_t = {call address, call arguments} = {msg.sender, ""}; the empty bytes literal is a
//           constant and is not controlled -> A = 1/2 = 0.5
//     g = 0 -> D = 1.0, M = 1.0, S(UC) = 0.6
//     R = 0.6 * (0.4*0.5 + 0.4*1.0 + 0.2*1.0) = 0.6 * 0.8 = 0.48
//     b = 1 -> P = 0.48 * 2^(-0.5) ~= 0.3394
//     CONFIRMED: `res` is never read, so the path with res = false reaches the write.
//
//   donate: ZERO targets. In 0.8 `+=` is checked, so it is no SC09 target, and there is no call.
//
// Under the original 0.4.2 pragma there would be two more targets, both SC09:
// `credit[to] += msg.value` (CONFIRMED -- msg.value is unbounded in the model, so the sum
// overflows for every storage state in D) and `credit[msg.sender] -= amount` (REFUTED -- the IF
// puts credit[msg.sender] >= amount into PC).
pragma solidity ^0.8.0;

contract ReentrancyIf {
    mapping(address => uint256) public credit;

    function donate(address to) public payable {
        credit[to] += msg.value;
    }

    function withdraw(uint256 amount) public {
        if (credit[msg.sender] >= amount) {
            (bool res, ) = msg.sender.call{value: amount}("");
            credit[msg.sender] -= amount;
        }
    }
}
