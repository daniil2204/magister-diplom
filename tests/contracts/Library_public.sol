// Negative of Safemath_library: a PUBLIC library function is a DELEGATECALL to a separate, unknown
// contract, so it is NOT inlined. Compile with solc 0.4.24. The result of `a.addPub(b)` is opaque --
// a fresh symbol -- so s is not controlled and `s + 1` is not an OV target. No target at all, and in
// the engine the opaque result makes the overflow unprovable (fresh symbol, no path constraint).
pragma solidity 0.4.24;

library PubMath {
    function addPub(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}

contract PubLibraryUser {
    using PubMath for uint256;
    mapping(address => uint256) public balances;

    function store(uint256 a, uint256 b) public {
        uint256 s = a.addPub(b);
        balances[msg.sender] = s + 1;
    }
}
