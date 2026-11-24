// SC08 cross-function reentry fixture: the classic DAO shape a single-function lock does not stop.
// Compile with solc 0.8.x (tests pin 0.8.20).
//
// `withdraw` is `nonReentrant`, so re-entering `withdraw` itself is unsat (locked == true in the
// snapshot Sigma_i). But `transfer` is NOT guarded: during the external call in `withdraw` the
// attacker re-enters `transfer`, where `balances[msg.sender]` still holds the pre-zero value, and
// moves it out. The re-entry candidate g is therefore `transfer`, not `withdraw`.
//
// Why `transfer` is a candidate (the finalised criterion): on a reachable path it has an EXPLICIT
// condition reading v -- `require(balances[msg.sender] >= amount)` reads `balances` -- and AFTER it
// performs a value action: `balances[msg.sender] -= amount` writes a mapping(address => uint). It is
// reachable in Sigma_i because it never checks `locked`. `deposit` is still excluded (no explicit
// condition reads `balances`), and `withdraw` as a candidate is unsat (its own lock).
//
// Expected targets: exactly ONE RE target -- the write `balances[msg.sender] = 0` after the call in
// `withdraw` -- and it must be CONFIRMED, with the re-entry function reported as `transfer`. The
// write `locked = false` in the modifier tail is not a target (lock-variable rule). `transfer` and
// `deposit` carry no targets (0.8 checked arithmetic, no external call).
//
// Control values for the RE target (identical to Vault_fixed_guard: same guarded `withdraw`):
//   E_t = {call address, value} = {msg.sender, amount} -> A = 1/2 = 0.5
//   g = 1 (require(!locked) dominates the target) -> D = 1/(1+1) = 0.5
//   M = 1 (the entry point transfers ether)
//   R = 1.0 * (0.4*0.5 + 0.4*0.5 + 0.2*1.0) = 0.6
//   b = 3 (require(!locked), require(amount > 0), require(ok)) -> P = 0.6 * 4^(-0.5) = 0.3
pragma solidity ^0.8.0;

contract ReentrancyCross {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable { balances[msg.sender] += msg.value; }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
