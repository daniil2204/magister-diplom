// Paired fixed version of Vault.sol: reentrancy lock.
// Compile with solc 0.8.x (tests pin 0.8.20).
// Expected targets: exactly ONE RE target -- the write `balances[msg.sender] = 0` after the
// call. It must be REFUTED: a second-level entry into any public function reading or writing
// `balances` is unsat because `locked == true` at the moment of the call.
//
// The write `locked = false` in the modifier tail also follows the call and matches the static
// rule for SC08, but a lock variable never produces an RE target: it is the protection
// mechanism, not the flaw. Otherwise every `nonReentrant` would add one spurious target per
// function, and a target the symbolic stage did not reach in time would be a false positive in
// moderate mode.
//
// Control values:
//   E_t = {call address, value} = {msg.sender, amount} -> A = 1/2 = 0.5
//   g = 1 (the lock check require(!locked) dominates the target) -> D = 1/(1+1) = 0.5
//   M = 1 (the entry point transfers ether)
//   R = 1.0 * (0.4*0.5 + 0.4*0.5 + 0.2*1.0) = 0.6
//   b = 3 (require(!locked), require(amount > 0), require(ok))
//   P = 0.6 * 4^(-0.5) = 0.3
pragma solidity ^0.8.0;

contract VaultFixedGuard {
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
}
