pragma solidity ^0.8.4;

contract C {
    function f() internal returns (uint a) {
        assembly {
            a := shr(a, 8)
        }
    }

    function g() internal returns (uint b) {
        assembly {
            b := shr(b, 8)
        }
    }
}