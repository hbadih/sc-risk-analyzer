// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// TODO: add access control
contract Vulnerable {

    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");

        balances[msg.sender] -= amount;
    }

    function withdrawAll() external {
        // no access control
    }

    function badAuth() external view returns (bool) {
        return tx.origin == msg.sender;
    }
}
