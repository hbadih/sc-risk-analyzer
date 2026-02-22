use sc_risk_analyzer::analyzer::analyze;

#[test]
fn detects_cross_function_reentrancy_graph() {
    let code = r#"
    pragma solidity ^0.8.0;

    contract ReentrancyCross {
        mapping(address => uint256) public balances;

        function withdrawAll() external {
            uint256 amt = balances[msg.sender];
            _payout(msg.sender, amt);
            _update(msg.sender, amt);
        }

        function _payout(address to, uint256 amt) internal {
            (bool ok,) = to.call{value: amt}("");
            require(ok);
        }

        function _update(address who, uint256 amt) internal {
            balances[who] -= amt;
        }
    }
    "#;

    let findings = analyze(code);
    assert!(findings.iter().any(|f| f.rule == "REENTRANCY_CALL_CHAIN_GRAPH"));
}