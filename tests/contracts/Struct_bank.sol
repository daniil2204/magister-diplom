// Struct fixture: mapping(address => Account) with two fields, to pin down struct flattening.
// Compile with solc 0.8.x (tests pin 0.8.20). Arithmetic is checked here, so no OV targets.
//
// Expected targets: ONE (RE, write `accounts[msg.sender].balance = 0` after the call).
//   withdraw: E_t = {msg.sender, amount}; amount is `accounts[msg.sender].balance`, i.e. storage,
//     so A = 0.5 exactly as in Vault -- the struct field changes nothing about controllability.
//     g = 0 -> D = 1.0, M = 1 (the entry point moves ether) -> R = 1.0 * (0.4*0.5 + 0.4 + 0.2) = 0.8
//     b = 2 (require(amount > 0), require(ok)) -> P = 0.8 * 3^(-0.5) ~= 0.462
//     CONFIRMED.
//   bump: writes `.nonce` only, no call -> no target. It exists to show that a write to one field
//     leaves the other field's term alone.
//   peek / snapshot: `storage` is a reference and `memory` is a copy. `snapshot` writes through a
//     memory copy, so storage does not change and no target is produced.
pragma solidity ^0.8.0;

contract Struct_bank {
    struct Account {
        uint256 balance;
        uint256 nonce;
    }

    mapping(address => Account) public accounts;

    function deposit() external payable {
        accounts[msg.sender].balance += msg.value;
    }

    function bump() external {
        accounts[msg.sender].nonce += 1;
    }

    function withdraw() external {
        uint256 amount = accounts[msg.sender].balance;
        require(amount > 0);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        accounts[msg.sender].balance = 0;
    }

    // A storage pointer: writing through it changes storage.
    function peek(address who, uint256 value) external {
        Account storage account = accounts[who];
        account.balance = value;
    }

    // A memory copy: writing through it changes nothing.
    function snapshot(address who, uint256 value) external view returns (uint256) {
        Account memory account = accounts[who];
        account.balance = value;
        return account.balance;
    }
}
