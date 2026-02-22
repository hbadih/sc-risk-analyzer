// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CrossFunction {

    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        _withdrawInternal();
    }

    function _withdrawInternal() internal {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No funds");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Call failed");

        balances[msg.sender] = 0;
    }
}
