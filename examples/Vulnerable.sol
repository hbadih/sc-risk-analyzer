// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// IERC20 interface should be OUTSIDE the contract
interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
}

// TODO: add access control
contract Vulnerable {

    address public target;
    IERC20 public token;

    mapping(address => uint256) public balances;

    constructor(address _target, address _token) {
        target = _target;
        token = IERC20(_token);
    }

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

    // -------------------------
    // NEW TEST FUNCTIONS
    // -------------------------

    function testDelegate(bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
    }

    function testSelfdestruct() external {
        selfdestruct(payable(msg.sender));
    }

    function testUncheckedTransfer(uint256 amount) external {
        token.transfer(msg.sender, amount);
    }
}
