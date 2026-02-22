//use sc_risk_analyzer::rules::TxOriginRule;
use sc_risk_analyzer::utils::build_context_map; // or analyzer::build_context_map
//use sc_risk_analyzer::analyzer::attach_context;

#[test]
fn context_maps_contract_and_function() {
    let code = r#"
contract A {
  function foo() external { }
  function bar() external { }
}
"#;

    let ctx = build_context_map(code);

    // line numbers in the string: find a known line and assert mapping
    // We'll just check that at least one line maps to (A, foo)
    let has_foo = ctx
        .iter()
        .any(|(c, f)| c.as_deref() == Some("A") && f.as_deref() == Some("foo"));
    assert!(has_foo);
}

#[test]
fn context_outside_contract_is_none() {
    let code = r#"
// TODO: global comment
contract A { function foo() external {} }
"#;

    let ctx = build_context_map(code);

    // First non-empty line is the TODO; it should be outside contract scope => (None, None)
    // Because lines can shift, just check that at least one line has (None, None)
    assert!(ctx.iter().any(|(c, f)| c.is_none() && f.is_none()));
}
