// Minimal SC06 fixture (unchecked low-level call). Compile with solc 0.8.x (tests pin 0.8.20).
// Positive and negative in one contract, like Overflow_args.sol.
//
// Expected targets: TWO UC targets.
//   payout: ONE UC target -- the write `balances[to] = 0` AFTER the unchecked call. The target is
//     the write, not the call: phi_UC (2.7) is lcall_i(a, r_i) AND r_i = false AND write_j, j > i.
//     E_t = {call address, call arguments} = {to, ""} -> to is an argument (controlled),
//           "" is a constant -> A = 1/2 = 0.5
//     g = 0 -> D = 1.0
//     M = 1 (the entry point transfers ether and writes mapping(address => uint))
//     S(UC) = 0.6
//     R = 0.6 * (0.4*0.5 + 0.4*1.0 + 0.2*1.0) = 0.6 * 0.8 = 0.48
//     b = 0 -> P = 0.48
//     CONFIRMED: the callee may revert, so r = false is reachable and the write still happens.
//
//   payoutSend: ONE UC target -- `send` reports failure through a return value just like `call`,
//     so SWC-104 covers it (this is Slither's `unchecked-send`). It is the only fixture where
//     an LCALL event comes from something other than `.call`.
//     E_t = {to, amount}: both are arguments -> A = 1.0. Whether Slither counts the value as a
//           call argument does not matter here -- both candidates are controlled.
//     g = 0 -> D = 1.0, M = 1, b = 0
//     R = 0.6 * (0.4*1.0 + 0.4*1.0 + 0.2*1.0) = 0.6, P = 0.6
//     CONFIRMED, for the same reason as payout.
//     NO RE target: 2300 gas is not enough to re-enter, so `send` never produces one.
//
//   payoutChecked: ZERO targets. `require(ok)` makes r_i = false unreachable at the write.
//
// No RE target anywhere in this fixture: `balances` is not read before the call, so the "v read
// before i" conjunct of phi_RE (2.6) fails. Vault.sol is the RE positive; this fixture isolates UC.
pragma solidity ^0.8.0;

contract UncheckedCall {
    mapping(address => uint256) public balances;

    function payout(address to, uint256 amount) external {
        to.call{value: amount}("");
        balances[to] = 0;
    }

    function payoutSend(address payable to, uint256 amount) external {
        to.send(amount);
        balances[to] = 0;
    }

    function payoutChecked(address to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
        balances[to] = 0;
    }
}
