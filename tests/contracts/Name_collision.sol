// OV fixture for call FRAMES. Compile with solc 0.4.24 (all arithmetic unchecked). The caller and
// the callee both name their locals `a` and `b`, so a flat variable map would let the inner call's
// arguments clobber the caller's -- and the guarded subtraction would be judged on the wrong values.
//   outer target: `a - b`, guarded by require(a >= b), so a >= b on the path => a <u b is unsat
//     => REFUTED, but only if the caller's a, b survive the call inner(b, a).
//   With a flat rho: inner(b, a) binds a := outer.b, b := outer.a; after the call `a - b` reads the
//     swapped values and underflows => CONFIRMED (wrong). Frames keep the two activations apart.
//   E_t = {a, b} -> A = 1 (both arguments), D = 1, M = 1; R = 0.8; b = 1 (the require) -> P = 0.566.
// `inner` itself holds a separate OV target (b - a) that belongs to the function `inner`, not here.
pragma solidity 0.4.24;

contract NameCollision {
    mapping(address => uint256) public balances;

    function inner(uint256 a, uint256 b) internal returns (uint256) {
        return a - b;
    }

    function outer(uint256 a, uint256 b) public {
        require(a >= b);
        uint256 r = inner(b, a);
        r;
        balances[msg.sender] = a - b;
    }
}
