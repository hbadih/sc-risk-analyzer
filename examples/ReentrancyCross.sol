// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyCross {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawAll() external {
        uint256 amt = balances[msg.sender];
        _payout(msg.sender, amt);      // external call happens in helper
        _update(msg.sender, amt);      // state update happens in helper
    }

    function _payout(address to, uint256 amt) internal {
        (bool ok,) = to.call{value: amt}("");
        require(ok);
    }

    function _update(address who, uint256 amt) internal {
        balances[who] -= amt;
    }
}