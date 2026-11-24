// Fixed reference contract: must match the thesis listing (Listing 1.1) exactly.
// Compile with solc 0.8.x (tests pin 0.8.20). In 0.8 `+=` in deposit is checked => no OV target.
// Expected targets: exactly ONE (RE, write `balances[msg.sender] = 0`). No UC (result checked by require(ok)).
pragma solidity ^0.8.0;

// Control values for the RE target (balances write after call): R = 0.8, b = 2, P ~= 0.462.
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
