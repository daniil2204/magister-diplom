// Minimal SC10 fixture (controlled delegatecall). Compile with solc 0.8.x (tests pin 0.8.20).
// V_auth is EMPTY: no state variable is ever compared with msg.sender. That is deliberate --
// the method treats an unguarded write to the proxy implementation address as a real
// vulnerability, not as an artefact of the empty set.
//
// `implementation` is the destination of a delegatecall, so writing it is a Priv operation
// ("запис адреси реалізації проксі") even though it is not in V_auth.
//
// Expected targets: THREE -- two DC and one AC.
//
//   forward: ONE DC target -- the delegatecall itself (for DC the target IS the operation).
//     E_t = {delegatecall address, calldata} = {target, data}, both arguments -> A = 1.0
//     g = 0 -> D = 1.0
//     M = 0.5 -- delegatecall carries no value and the contract writes no mapping(address=>uint)
//     R = 1.0 * (0.4*1.0 + 0.4*1.0 + 0.2*0.5) = 0.90
//     b = 0 -> P = 0.90
//     CONFIRMED: phi_DC (2.10) is dcall_i(a) AND Ctrl(a), and a is an argument.
//
//   run: ONE DC target. This is the negative case for phi_DC.
//     E_t = {implementation, data} -- implementation is a state variable, so NOT controlled
//       -> A = 1/2 = 0.5
//     g = 0 -> D = 1.0, M = 0.5
//     R = 1.0 * (0.4*0.5 + 0.4*1.0 + 0.2*0.5) = 0.2 + 0.4 + 0.1 = 0.70
//     b = 0 -> P = 0.70
//     REFUTED: the destination comes from X_sto, so Ctrl(a) is false.
//
//   upgrade: ONE AC target -- the write `implementation = impl`.
//     E_t = {msg.sender, impl}, both controlled -> A = 1.0
//     g = 0 -> D = 1.0, M = 0.5
//     R = 0.90, b = 0 -> P = 0.90
//     CONFIRMED: anybody can repoint the proxy.
//
// The fixture avoids `msg.data` on purpose: X_env (2.3) is {msg.sender, tx.origin, msg.value},
// so msg.data has no defined controllability in the method. Real proxies forward msg.data.
pragma solidity ^0.8.0;

contract DelegatecallProxy {
    address public implementation;

    function upgrade(address impl) public {
        implementation = impl;
    }

    function forward(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    function run(bytes calldata data) external {
        implementation.delegatecall(data);
    }
}
