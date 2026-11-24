// Flattening fixture: nested structs, a struct behind a mapping behind a struct, and an array of
// structs. Compile with solc 0.8.x (tests pin 0.8.20).
//
// Expected targets: NONE. There is no arithmetic outside the checked default, no external call
// and no privileged operation, so the static stage has nothing to report. The fixture exists for
// the translator alone: it pins how a type is taken apart into terms.
//
// Expected terms, by `flatten`:
//   Outer                      -> inner.a : uint256, inner.who : address, b : uint256
//   Outer[3]                   -> the same three, each wrapped in Array(uint256, .)
//   mapping(uint256 => Deep)   -> m.a : Array(uint256, Array(uint256, uint256)),
//                                 m.who, c -- the outer mapping key comes first, so
//                                 `deeps[i].m[j].a` is Select(Select(deeps.m.a, i), j).
//
// `wipeDeep` must stay unsupported: Solidity's `delete` leaves the mapping inside Deep untouched,
// and the method does not model that.
pragma solidity ^0.8.0;

contract Struct_nested {
    struct Inner {
        uint256 a;
        address who;
    }
    struct Outer {
        Inner inner;
        uint256 b;
    }
    struct Deep {
        mapping(uint256 => Inner) m;
        uint256 c;
    }

    Outer public one;
    Outer[3] private row;
    mapping(uint256 => Deep) private deeps;

    function setOne(uint256 v, address w) external {
        one = Outer(Inner(v, w), v);
    }

    function setRow(uint256 i, uint256 v, address w) external {
        row[i] = Outer(Inner(v, w), v);
    }

    function setDeep(uint256 i, uint256 j, uint256 v) external {
        deeps[i].m[j].a = v;
        deeps[i].c = v;
    }

    function readRow(uint256 i) external view returns (address) {
        return row[i].inner.who;
    }

    function wipeOne() external {
        delete one;
    }

    function wipeDeep(uint256 i) external {
        delete deeps[i];
    }

    function copyOut() external view returns (uint256) {
        Outer memory o = one;
        return o.inner.a;
    }
}
