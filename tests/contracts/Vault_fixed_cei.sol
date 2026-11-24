// Paired fixed version of Vault.sol: checks-effects-interactions.
// Compile with solc 0.8.x (tests pin 0.8.20).
// Expected targets: ZERO. The balance is zeroed BEFORE the call, so no state write follows the
// call and the static stage alone discards the candidate -- neither RE nor UC survives.
// No control values: there is no target to score.
pragma solidity ^0.8.0;

contract VaultFixedCEI {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
