use sc_risk_analyzer::analyzer::attach_context;
use sc_risk_analyzer::rules::Rule;
use sc_risk_analyzer::rules::TxOriginRule;
use sc_risk_analyzer::utils::build_context_map;

#[test]
fn detects_tx_origin() {
    let code = r#"
contract A {
  function badAuth() external view returns (bool) {
    return tx.origin == msg.sender;
  }
}
"#;

    let rule = TxOriginRule;
    let findings = rule.check(code);

    // attach contract/function context like the real pipeline does
    let ctx = build_context_map(code);
    let findings = attach_context(findings, &ctx);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "TX_ORIGIN");
    assert_eq!(findings[0].contract.as_deref(), Some("A"));
    assert_eq!(findings[0].function.as_deref(), Some("badAuth"));
}
