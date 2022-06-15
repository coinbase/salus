pragma solidity ^0.8.4;

contract C {
    address zeroAddr = address(0x0);

    function f() public payable {
        payable(zeroAddr).transfer(msg.value);
    }
}
