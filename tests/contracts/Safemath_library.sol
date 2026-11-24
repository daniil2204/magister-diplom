// OV fixture for INTERNAL library-call inlining (classic SafeMath). Compile with solc 0.4.24 (all
// arithmetic unchecked). `a.add(b)` is an internal library function: solc copies it into the caller,
// so the engine inlines it as an exact model and the static stage taints its result like an ordinary
// internal call.
//   store target: `s + 1`, where s = a.add(b) = a + b.
//   With inlining: s is symbolic (a + b), so (a + b) + 1 overflows when a + b = 2^256-1 => CONFIRMED
//     (strong condition holds: storage is not involved).
//   chain: `s = a.add(b).sub(c)` is TWO internal library calls in ONE node (the lifted
//     one-call-per-node limit); s = (a + b) - c is symbolic, so `s + 1` is an OV target too, scored
//     exactly like store. CONFIRMED proves both calls inline and both returns cross the node.
//   E_t = {s, 1} -> A = 1/2 = 0.5 (1 is a constant), D = 1 (no V_auth), M = 1 (mapping balances).
//   R = 0.8 * (0.4*0.5 + 0.4*1 + 0.2*1) = 0.64; b = 0; P = 0.640 (both store and chain).
pragma solidity 0.4.24;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a - b;
    }
}

contract SafeMathLibraryUser {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;

    function store(uint256 a, uint256 b) public {
        uint256 s = a.add(b);
        balances[msg.sender] = s + 1;
    }

    function chain(uint256 a, uint256 b, uint256 c) public {
        uint256 s = a.add(b).sub(c);
        balances[msg.sender] = s + 1;
    }
}
