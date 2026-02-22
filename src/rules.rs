use crate::models::{Evidence, Finding, Severity};
use crate::utils::{
    compute_risk, first_match, first_match_any, round2,
    split_functions_with_start_lines,
};
//use crate::utils::build_context_map;

pub trait Rule {
    fn id(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;

    // ✅ new: rule-specific evidence message
    fn evidence_message(&self) -> &'static str {
        "Matched pattern in source"
    }

    fn check(&self, code: &str) -> Vec<Finding>;
}

fn make_finding(
    rule: &dyn Rule,
    line: Option<usize>,
    evidence_snippet: String,
    confidence: f32,
) -> Finding {
    let sev = rule.severity();
    let confidence = round2(confidence);
    let risk = compute_risk(sev, confidence);
    Finding {
        rule: rule.id().to_string(),
        severity: sev,
        description: rule.description().to_string(),

        contract: None,
        function: None,

        line,
        evidence: Evidence::single(
            rule.description(),
            rule.evidence_message(),
            line,
            evidence_snippet,
        ),

        confidence,
        risk_score: risk,
    }
}

pub struct TxOriginRule;
impl Rule for TxOriginRule {
    fn id(&self) -> &'static str {
        "TX_ORIGIN"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "Use of tx.origin for authorization is unsafe"
    }

    fn evidence_message(&self) -> &'static str {
        "`tx.origin` used (unsafe for authorization checks)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        first_match(code, "tx.origin")
            .map(|(ln, ev)| vec![make_finding(self, Some(ln), ev, 0.95)])
            .unwrap_or_default()
    }
}

pub struct DelegatecallRule;
impl Rule for DelegatecallRule {
    fn id(&self) -> &'static str {
        "DELEGATECALL"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "delegatecall detected (high risk). Ensure target is trusted and call path is access-controlled"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        first_match(code, "delegatecall")
            .map(|(ln, ev)| vec![make_finding(self, Some(ln), ev, 0.85)])
            .unwrap_or_default()
    }
}

pub struct PayableExternalCallRule;
impl Rule for PayableExternalCallRule {
    fn id(&self) -> &'static str {
        "PAYABLE_EXTERNAL_CALL"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "External call with value detected (reentrancy and fund-drain risk)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        // `.call{value: ...}` or `call{value: ...}`
        if let Some((ln, ev)) = first_match(code, ".call{value") {
            vec![make_finding(self, Some(ln), ev, 0.90)]
        } else if let Some((ln, ev)) = first_match(code, "call{value") {
            vec![make_finding(self, Some(ln), ev, 0.90)]
        } else {
            vec![]
        }
    }
}

pub struct LowLevelCallRule;
impl Rule for LowLevelCallRule {
    fn id(&self) -> &'static str {
        "LOW_LEVEL_CALL"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn description(&self) -> &'static str {
        "Low-level call detected; ensure return value is checked"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        // Avoid duplicating PAYABLE_EXTERNAL_CALL; match `.call(` OR `call{` except value-calls
        let mut m = first_match(code, ".call(");

        if m.is_none() {
            let tmp = first_match(code, "call{");
            if let Some((_, ref ev)) = tmp {
                if !ev.contains("call{value") {
                    m = tmp;
                }
            }
        }

        m.map(|(ln, ev)| vec![make_finding(self, Some(ln), ev, 0.75)])
            .unwrap_or_default()
    }
}

pub struct ReentrancyHeuristicRule;
impl Rule for ReentrancyHeuristicRule {
    fn id(&self) -> &'static str {
        "REENTRANCY_HEURISTIC"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "Possible reentrancy risk: external call and state update in same function (heuristic)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        for (start_line, block) in split_functions_with_start_lines(code) {
            let call = first_match_any(&block, &[".call{value", "call{value", ".call("]);
            let update = first_match_any(
                &block,
                &[
                    "+=",
                    "-=",
                    "++",
                    "--",
                    "balances[msg.sender] =",
                    "balances[msg.sender] +=",
                    "balances[msg.sender] -=",
                    "balanceOf[msg.sender] =",
                ],
            );

            if let (Some((call_rel, call_snip)), Some((upd_rel, upd_snip))) = (call, update) {
                let call_ln = start_line + call_rel - 1;
                let upd_ln = start_line + upd_rel - 1;

                let has_value =
                    call_snip.contains("call{value") || call_snip.contains(".call{value");
                let mut confidence = if call_rel < upd_rel { 0.85 } else { 0.55 };
                if has_value {
                    confidence = (confidence + 0.05_f32).min(0.95_f32);
                }

                let sev = self.severity();
                let confidence = round2(confidence);
                let risk = compute_risk(sev, confidence);

                let evidence = Evidence::two_items(
                    self.description(),
                    "External call detected (possible reentrancy entry point)",
                    Some(call_ln),
                    call_snip,
                    "State update detected (state changes found; ordering may matter)",
                    Some(upd_ln),
                    upd_snip,
                );

                return vec![Finding {
                    rule: self.id().to_string(),
                    severity: sev,
                    description: self.description().to_string(),
                    contract: None,
                    function: None,
                    line: Some(call_ln),
                    evidence,
                    confidence,
                    risk_score: risk,
                }];
            }
        }

        vec![]
    }
}

pub struct MissingAccessControlRule;
impl Rule for MissingAccessControlRule {
    fn id(&self) -> &'static str {
        "MISSING_ACCESS_CONTROL"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn description(&self) -> &'static str {
        "Sensitive function may be missing access control (heuristic)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        let has_ac = code.contains("onlyOwner")
            || code.contains("onlyRole")
            || code.contains("AccessControl")
            || code.contains("Ownable");

        if has_ac {
            return vec![];
        }

        let sensitive = [
            "function withdrawAll",
            "function mint",
            "function burn",
            "function upgrade",
            "function setOwner",
            "function setAdmin",
            "function pause",
            "function unpause",
            "function withdraw",
        ];

        for pat in sensitive {
            if let Some((ln, ev)) = first_match(code, pat) {
                return vec![make_finding(self, Some(ln), ev, 0.60)];
            }
        }

        vec![]
    }
}

pub struct TodoCommentRule;
impl Rule for TodoCommentRule {
    fn id(&self) -> &'static str {
        "TODO_COMMENT"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn description(&self) -> &'static str {
        "TODO/FIXME comment found (potential unfinished security logic)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        if let Some((ln, ev)) = first_match(code, "TODO") {
            vec![make_finding(self, Some(ln), ev, 0.40)]
        } else if let Some((ln, ev)) = first_match(code, "FIXME") {
            vec![make_finding(self, Some(ln), ev, 0.40)]
        } else {
            vec![]
        }
    }
}

pub struct SelfdestructRule;
impl Rule for SelfdestructRule {
    fn id(&self) -> &'static str {
        "SELFDESTRUCT"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "selfdestruct/suicide detected. Destruction can break assumptions and lock or drain funds"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        if let Some((ln, ev)) = first_match(code, "selfdestruct") {
            vec![make_finding(self, Some(ln), ev, 0.95)]
        } else if let Some((ln, ev)) = first_match(code, "suicide(") {
            vec![make_finding(self, Some(ln), ev, 0.95)]
        } else {
            vec![]
        }
    }
}

pub struct UncheckedErc20TransferRule;
impl Rule for UncheckedErc20TransferRule {
    fn id(&self) -> &'static str {
        "UNCHECKED_ERC20_TRANSFER"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn description(&self) -> &'static str {
        "Possible unchecked ERC20 transfer/transferFrom return value. Consider require(token.transfer(...)) or SafeERC20"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        for (ln, line) in code.lines().enumerate() {
            let line_no = ln + 1;
            let s = line.trim();

            let is_transfer = s.contains(".transfer(") || s.contains(".transferFrom(");
            if !is_transfer {
                continue;
            }

            // Skip if obviously checked
            let checked = s.contains("require(")
                || s.contains("assert(")
                || s.contains("if (")
                || s.contains("if(");

            // Skip if assigned to a bool
            let assigned = s.contains("= ")
                && (s.contains("bool ") || s.contains("=token.") || s.contains("= token."));

            if checked || assigned {
                continue;
            }

            out.push(make_finding(self, Some(line_no), s.to_string(), 0.65));
        }

        out
    }
}
