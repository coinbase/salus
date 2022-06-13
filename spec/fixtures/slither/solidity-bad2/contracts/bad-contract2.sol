pragma solidity ^0.8.4;

contract D {
    function g() internal returns (uint b) {
        assembly {
            b := shr(b, 8)
        }
    }
}
