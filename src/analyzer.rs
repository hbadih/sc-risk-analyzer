// src/analyzer.rs

use crate::models::{Evidence, Finding, Severity, Summary};
use crate::rules::{
    DelegatecallRule, LowLevelCallRule, MissingAccessControlRule, PayableExternalCallRule,
    ReentrancyHeuristicRule, Rule, SelfdestructRule, TodoCommentRule, TxOriginRule,
    UncheckedErc20TransferRule,
};
use crate::utils::{build_context_map, compute_risk};

use crate::analysis::callgraph::CallGraph;
use crate::analysis::callsites::extract_callsites;
use crate::analysis::summaries::{compute_local_summaries, propagate_summaries};
use crate::analysis::symbols::{ContractId, FnDecl, FunctionId, SymbolIndex};

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct FunctionSlice {
    pub name: String,
    pub start_line: usize, // 1-based
    pub text: String,      // full function source (as a string)
}

#[derive(Debug, Clone)]
pub struct FunctionSpan {
    pub contract: Option<String>,
    pub name: String,
    pub start_line: usize, // 1-based
    pub end_line: usize,   // 1-based
    pub header: String,    // original function header line (for checking visibility)
}

// -----------------------------
// Helpers for graph-based evidence
// -----------------------------
fn mk_fid(contract: &str, fname: &str) -> FunctionId {
    FunctionId {
        contract: ContractId {
            name: contract.to_string(),
        },
        sig_key: format!("{}::{}", contract, fname),
        display_name: format!("{}::{}", contract, fname),
    }
}

fn mk_span_key(contract: &str, fname: &str) -> String {
    format!("{}::{}", contract, fname)
}

/// Find first match in a function body. Returns (1-based line offset in body, snippet).
fn first_match_in_body(body: &str, patterns: &[&str]) -> Option<(usize, String)> {
    for (i, line) in body.lines().enumerate() {
        for p in patterns {
            if line.contains(p) {
                return Some((i + 1, line.trim().to_string()));
            }
        }
    }
    None
}

fn looks_like_storage_write(line: &str) -> bool {
    let l = line.trim();

    // obvious mutations
    if l.contains("+=") || l.contains("-=") || l.contains("++") || l.contains("--") {
        return true;
    }

    // mapping/array assignment: something[...] = ...
    if l.contains('[') && l.contains("]") && l.contains('=') && !l.contains("==") {
        // avoid `uint x = ...` local declarations
        let starts_local = l.starts_with("uint")
            || l.starts_with("int")
            || l.starts_with("bool")
            || l.starts_with("string")
            || l.starts_with("bytes")
            || l.starts_with("address");

        return !starts_local;
    }

    false
}

/// Reachable nodes in callgraph from a starting FunctionId (including start).
fn reachable_fids(callgraph: &CallGraph, start: &FunctionId) -> Vec<FunctionId> {
    use std::collections::{HashMap as StdHashMap, VecDeque};

    // map FunctionId -> index
    let mut idx: StdHashMap<FunctionId, usize> = StdHashMap::new();
    for (i, f) in callgraph.nodes.iter().enumerate() {
        idx.insert(f.clone(), i);
    }

    let start_i = match idx.get(start) {
        Some(i) => *i,
        None => return vec![],
    };

    let mut seen = vec![false; callgraph.nodes.len()];
    let mut q = VecDeque::new();
    let mut out: Vec<FunctionId> = Vec::new();

    seen[start_i] = true;
    q.push_back(start_i);

    while let Some(i) = q.pop_front() {
        out.push(callgraph.nodes[i].clone());
        for e in &callgraph.adj[i] {
            let j = e.to;
            if j < seen.len() && !seen[j] {
                seen[j] = true;
                q.push_back(j);
            }
        }
    }

    out
}

// -----------------------------
// Solidity parsing (heuristic)
// -----------------------------

/// Parse identifier name immediately after a keyword.
/// Example: "function withdraw() external {" -> Some("withdraw")
pub fn parse_name_after_keyword(line: &str, keyword: &str) -> Option<String> {
    let s = line.trim();
    if !s.starts_with(keyword) {
        return None;
    }

    let rest = s[keyword.len()..].trim_start();

    let mut name = String::new();
    for ch in rest.chars() {
        if ch == '(' || ch.is_whitespace() {
            break;
        }
        if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            name.push(ch);
        } else {
            break;
        }
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Build spans by scanning for `function NAME` and matching braces.
pub fn build_function_spans(code: &str) -> Vec<FunctionSpan> {
    let mut spans: Vec<FunctionSpan> = Vec::new();
    let mut current_contract: Option<String> = None;

    let lines: Vec<&str> = code.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // contract / interface / library
        if let Some(name) = parse_name_after_keyword(trimmed, "contract")
            .or_else(|| parse_name_after_keyword(trimmed, "interface"))
            .or_else(|| parse_name_after_keyword(trimmed, "library"))
        {
            current_contract = Some(name);
        }

        // function NAME ...
        if let Some(fname) = parse_name_after_keyword(trimmed, "function") {
            let header = trimmed.to_string();
            let start_line = i + 1;

            // Find end_line by brace matching.
            let mut depth: i32 = 0;
            let mut saw_open = false;
            let mut end_line = start_line;

            let mut j = i;
            while j < lines.len() {
                let l = lines[j];

                for ch in l.chars() {
                    if ch == '{' {
                        depth += 1;
                        saw_open = true;
                    } else if ch == '}' {
                        depth -= 1;
                    }
                }

                end_line = j + 1;

                if saw_open && depth == 0 {
                    break;
                }

                j += 1;
            }

            spans.push(FunctionSpan {
                contract: current_contract.clone(),
                name: fname,
                start_line,
                end_line,
                header,
            });

            i = end_line;
            continue;
        }

        i += 1;
    }

    spans
}

/// Extract the substring corresponding to a span (inclusive).
fn slice_span(code: &str, span: &FunctionSpan) -> String {
    let mut out = String::new();
    for (idx, line) in code.lines().enumerate() {
        let ln = idx + 1;
        if ln >= span.start_line && ln <= span.end_line {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Identify if a function is an "entrypoint": public/external (Solidity).
fn is_public_or_external(span: &FunctionSpan) -> bool {
    let h = span.header.as_str();
    h.contains(" public")
        || h.contains(" external")
        || h.contains("public ")
        || h.contains("external ")
}

/// Split Solidity code into functions, returning each function's name + start line + body.
///
/// Notes:
/// - simple brace-based parser (not a full Solidity parser)
pub fn split_functions_with_start_lines(code: &str) -> Vec<FunctionSlice> {
    let lines: Vec<&str> = code.lines().collect();
    let mut out: Vec<FunctionSlice> = Vec::new();

    let mut i: usize = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();

        if let Some(fname) = parse_name_after_keyword(trimmed, "function") {
            let start_line = i + 1;

            let mut func_lines: Vec<String> = vec![lines[i].to_string()];

            let mut brace_depth: i32 = 0;
            let mut saw_open_brace = false;

            for ch in lines[i].chars() {
                if ch == '{' {
                    brace_depth += 1;
                    saw_open_brace = true;
                } else if ch == '}' {
                    brace_depth -= 1;
                }
            }

            let mut j = i + 1;
            while j < lines.len() && !saw_open_brace {
                func_lines.push(lines[j].to_string());
                for ch in lines[j].chars() {
                    if ch == '{' {
                        brace_depth += 1;
                        saw_open_brace = true;
                    } else if ch == '}' {
                        brace_depth -= 1;
                    }
                }
                j += 1;
            }

            if !saw_open_brace {
                while j < lines.len() {
                    func_lines.push(lines[j].to_string());
                    if lines[j].contains(';') {
                        break;
                    }
                    j += 1;
                }

                out.push(FunctionSlice {
                    name: fname,
                    start_line,
                    text: func_lines.join("\n"),
                });

                i = j + 1;
                continue;
            }

            while j < lines.len() && brace_depth > 0 {
                func_lines.push(lines[j].to_string());

                for ch in lines[j].chars() {
                    if ch == '{' {
                        brace_depth += 1;
                    } else if ch == '}' {
                        brace_depth -= 1;
                    }
                }

                j += 1;
            }

            out.push(FunctionSlice {
                name: fname,
                start_line,
                text: func_lines.join("\n"),
            });

            i = j;
            continue;
        }

        i += 1;
    }

    out
}

// -----------------------------
// Optional older heuristic cross-function detector (kept, fixed)
// -----------------------------

/// Build a simple call graph: function -> called functions (by name)
pub fn build_call_graph(code: &str, spans: &[FunctionSpan]) -> HashMap<String, Vec<String>> {
    let names: HashSet<String> = spans.iter().map(|s| s.name.clone()).collect();
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();

    for s in spans {
        let body = slice_span(code, s);
        let mut callees: Vec<String> = Vec::new();

        for cand in names.iter() {
            if cand == &s.name {
                continue;
            }
            let needle1 = format!("{}(", cand);
            let needle2 = format!("{} ();", cand);

            if body.contains(&needle1) || body.contains(&needle2) {
                callees.push(cand.clone());
            }
        }

        graph.insert(s.name.clone(), callees);
    }

    graph
}

fn first_match_in_span(
    code: &str,
    span: &FunctionSpan,
    patterns: &[&str],
) -> Option<(usize, String, String)> {
    for (idx, line) in code.lines().enumerate() {
        let ln = idx + 1;
        if ln < span.start_line || ln > span.end_line {
            continue;
        }
        for p in patterns {
            if line.contains(p) {
                return Some((ln, format!("Matched `{}`", p), line.trim().to_string()));
            }
        }
    }
    None
}

/// Cross-function reentrancy (older heuristic): entry -> reachable external call + state update.
/// (This is separate from graph-based propagated approach.)
pub fn detect_reentrancy_call_chain(code: &str) -> Vec<Finding> {
    let spans = build_function_spans(code);
    let graph = build_call_graph(code, &spans);

    let by_name: HashMap<String, FunctionSpan> =
        spans.iter().cloned().map(|s| (s.name.clone(), s)).collect();

    let external_call_patterns = [".call{value", "call{value", ".call("];

    let mut findings: Vec<Finding> = Vec::new();

    for entry in spans.iter().filter(|s| is_public_or_external(s)) {
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = vec![entry.name.clone()];
        visited.insert(entry.name.clone());

        while let Some(cur) = stack.pop() {
            if let Some(nexts) = graph.get(&cur) {
                for n in nexts {
                    if visited.insert(n.clone()) {
                        stack.push(n.clone());
                    }
                }
            }
        }

        let mut call_hit: Option<(usize, String, String, Option<String>, String)> = None;
        let mut upd_hit: Option<(usize, String, String, Option<String>, String)> = None;

        for fname in visited.iter() {
            let span = match by_name.get(fname) {
                Some(s) => s,
                None => continue,
            };

            if call_hit.is_none() {
                if let Some((ln, msg, snip)) =
                    first_match_in_span(code, span, &external_call_patterns)
                {
                    call_hit = Some((ln, msg, snip, span.contract.clone(), span.name.clone()));
                }
            }

            if upd_hit.is_none() {
                let upd_patterns = ["-=", "+=", "balances[", "balances[msg.sender]"];
                if let Some((ln, msg, snip)) = first_match_in_span(code, span, &upd_patterns) {
                    upd_hit = Some((ln, msg, snip, span.contract.clone(), span.name.clone()));
                }
            }

            if call_hit.is_some() && upd_hit.is_some() {
                break;
            }
        }

        if let (Some(call), Some(upd)) = (call_hit.clone(), upd_hit.clone()) {
            let sev = Severity::High;
            let confidence: f32 = 0.8;
            let risk = compute_risk(sev, confidence);

            let (call_ln, _call_msg, call_snip, _call_contract, call_fn) = call;
            let (upd_ln, _upd_msg, upd_snip, _upd_contract, upd_fn) = upd;

            let evidence = Evidence::two_items(
                "Cross-function reentrancy risk: entry can reach external call + state update (heuristic)",
                &format!("External call reachable in `{}`", call_fn),
                Some(call_ln),
                call_snip,
                &format!("State update reachable in `{}`", upd_fn),
                Some(upd_ln),
                upd_snip,
            );

            findings.push(Finding {
                rule: "REENTRANCY_CALL_CHAIN".to_string(),
                severity: sev,
                description: "Possible cross-function reentrancy risk (heuristic call-chain)".to_string(),
                line: Some(entry.start_line),
                contract: entry.contract.clone(),
                function: Some(entry.name.clone()),
                evidence,
                confidence,
                risk_score: risk,
            });
        }
    }

    findings
}

// -----------------------------
// Main analysis entrypoint
// -----------------------------
pub fn analyze(code: &str) -> Vec<Finding> {
    // (Optional) keep if you want to debug splitting:
    // let funcs = split_functions_with_start_lines(code);
    // for f in &funcs { println!("DEBUG: function {} starts at line {}", f.name, f.start_line); }

    // ----------------------------
    // Build spans (contract + function boundaries)
    // ----------------------------
    let spans = build_function_spans(code);

    // Build span index: "Contract::fn" -> FunctionSpan
    let mut span_index: HashMap<String, FunctionSpan> = HashMap::new();
    for s in &spans {
        if let Some(c) = &s.contract {
            span_index.insert(mk_span_key(c, &s.name), s.clone());
        }
    }

    // ----------------------------
    // Build SymbolIndex
    // ----------------------------
    let mut decls: Vec<FnDecl> = Vec::new();
    for s in &spans {
        if let Some(contract_name) = &s.contract {
            decls.push(FnDecl {
                contract_name: contract_name.clone(),
                display_name: s.name.clone(),
                sig_key: format!("{}::{}", contract_name, s.name),
            });
        }
    }
    let symbols = SymbolIndex::from_decls(decls);

    // ----------------------------
    // Build CallGraph and function bodies
    // ----------------------------
    let mut callgraph = CallGraph::default();
    let mut bodies: HashMap<FunctionId, String> = HashMap::new();

    for s in &spans {
        let contract_name = match &s.contract {
            Some(c) => c,
            None => continue,
        };

        let caller = mk_fid(contract_name, &s.name);
        let body = slice_span(code, s);

        bodies.insert(caller.clone(), body.clone());

        let cs = extract_callsites(contract_name, &caller, &body, &symbols);
        callgraph.add_callsites(cs);
    }

    // ----------------------------
    // Summaries (graph propagation)
    // ----------------------------
    let mut summaries = compute_local_summaries(&callgraph, &bodies);
    propagate_summaries(&callgraph, &mut summaries);

    if std::env::var("SC_ANALYZER_DEBUG").is_ok() {
        eprintln!("DEBUG: callgraph.nodes = {}", callgraph.nodes.len());
        eprintln!("DEBUG: callgraph.callsites = {}", callgraph.callsites.len());
        eprintln!("DEBUG: summaries.len = {}", summaries.len());
    }
    // ----------------------------
    // Existing rules (unchanged)
    // ----------------------------
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(TxOriginRule),
        Box::new(DelegatecallRule),
        Box::new(PayableExternalCallRule),
        Box::new(LowLevelCallRule),
        Box::new(ReentrancyHeuristicRule),
        Box::new(MissingAccessControlRule),
        Box::new(TodoCommentRule),
        Box::new(SelfdestructRule),
        Box::new(UncheckedErc20TransferRule),
    ];

    let mut findings: Vec<Finding> = Vec::new();
    for rule in rules {
        findings.extend(rule.check(code));
    }

    // ----------------------------
    // Graph-based cross-function reentrancy (WITH witnesses)
    // ----------------------------
    let external_call_patterns = [
        ".call{",
        ".call(",
        ".delegatecall(",
        ".staticcall(",
        ".send(",
        ".transfer(",
    ];
    let _state_update_patterns = ["+=", "-=", "++", "--", " = ", "balances[", "]="];

    for s in spans.iter().filter(|s| is_public_or_external(s)) {
        let contract_name = match &s.contract {
            Some(c) => c,
            None => continue,
        };

        let entry_fid = mk_fid(contract_name, &s.name);

        let Some(sum) = summaries.get(&entry_fid) else { continue };
        if !(sum.has_external_call && sum.has_state_update) {
            continue;
        }

        let reachable = reachable_fids(&callgraph, &entry_fid);

        // (FunctionId, global_line, snippet)
        let mut ext_witness: Option<(FunctionId, usize, String)> = None;
        let mut upd_witness: Option<(FunctionId, usize, String)> = None;

        for fid in reachable {
            let body = match bodies.get(&fid) {
                Some(b) => b.as_str(),
                None => continue,
            };

            if ext_witness.is_none() {
                if let Some((off, snip)) = first_match_in_body(body, &external_call_patterns) {
                    if let Some(sp) = span_index.get(&fid.sig_key) {
                        let global_ln = sp.start_line + off - 1;
                        ext_witness = Some((fid.clone(), global_ln, snip));
                    }
                }
            }

            // if upd_witness.is_none() {
            //     if let Some((off, snip)) = first_match_in_body(body, &state_update_patterns) {
            //         if let Some(sp) = span_index.get(&fid.sig_key) {
            //             let global_ln = sp.start_line + off - 1;
            //             upd_witness = Some((fid.clone(), global_ln, snip));
            //         }
            //     }
            // }

            if upd_witness.is_none() {
                for (i, line) in body.lines().enumerate() {
                    if looks_like_storage_write(line) {
                        if let Some(sp) = span_index.get(&fid.sig_key) {
                            let global_ln = sp.start_line + (i + 1) - 1;
                            upd_witness = Some((fid.clone(), global_ln, line.trim().to_string()));
                        }
                        break;
                    }
                }
            }

            if ext_witness.is_some() && upd_witness.is_some() {
                break;
            }
        }

        let sev = Severity::High;
        let confidence: f32 = 0.75;
        let risk = compute_risk(sev, confidence);

        let (ext_msg, ext_ln, ext_snip) = match &ext_witness {
            Some((fid, ln, snip)) => (
                format!("External call reachable in `{}`", fid.sig_key),
                Some(*ln),
                snip.clone(),
            ),
            None => (
                "External call reachable (witness not located)".to_string(),
                Some(s.start_line),
                "".to_string(),
            ),
        };

        let (upd_msg, upd_ln, upd_snip) = match &upd_witness {
            Some((fid, ln, snip)) => (
                format!("State update reachable in `{}`", fid.sig_key),
                Some(*ln),
                snip.clone(),
            ),
            None => (
                "State update reachable (witness not located)".to_string(),
                Some(s.start_line),
                "".to_string(),
            ),
        };

        let evidence = Evidence::two_items(
            "Cross-function reentrancy risk (call-graph): entry reaches external call + state update",
            &ext_msg,
            ext_ln,
            ext_snip,
            &upd_msg,
            upd_ln,
            upd_snip,
        );

        findings.push(Finding {
            rule: "REENTRANCY_CALL_CHAIN_GRAPH".to_string(),
            severity: sev,
            description:
                "Possible cross-function reentrancy risk: reachable external call + state update across internal calls"
                    .to_string(),
            line: Some(s.start_line),
            contract: s.contract.clone(),
            function: Some(s.name.clone()),
            evidence,
            confidence,
            risk_score: risk,
        });
    }

    // ----------------------------
    // Attach context + sort (ONLY ONCE)
    // ----------------------------
    let ctx = build_context_map(code);
    findings = attach_context(findings, &ctx);
    findings.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
    findings
}

// Takes each finding line -> looks up ctx[line-1] -> fills finding.contract/finding.function
pub fn attach_context(
    mut findings: Vec<Finding>,
    ctx: &[(Option<String>, Option<String>)],
) -> Vec<Finding> {
    for f in &mut findings {
        if let Some(line) = f.line {
            if line == 0 {
                continue;
            }
            let idx = line.saturating_sub(1);
            if let Some((c, fun)) = ctx.get(idx) {
                f.contract = c.clone();
                f.function = fun.clone();
            }
        }
    }
    findings
}

pub fn summarize(findings: &[Finding]) -> Summary {
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut max_risk: f32 = 0.0;

    for f in findings {
        match f.severity {
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
        max_risk = max_risk.max(f.risk_score);
    }

    Summary {
        total: findings.len(),
        high,
        medium,
        low,
        max_risk,
    }
}

pub fn filter_findings(findings: Vec<Finding>, min_sev: Severity) -> Vec<Finding> {
    let min_rank = min_sev.rank();
    findings
        .into_iter()
        .filter(|f| f.severity.rank() >= min_rank)
        .collect()
}

pub fn print_text_report(file: &str, findings: &[Finding], summary: &Summary) {
    let _ = file;
    let _ = summary;
    for f in findings {
        let _line_str = f.line.map(|n| n.to_string()).unwrap_or("-".to_string());
        let _contract = f.contract.as_deref().unwrap_or("-");
        let _function = f.function.as_deref().unwrap_or("-");

        
        for item in &f.evidence.items {
            let _ln = item.line.map(|n| n.to_string()).unwrap_or("-".to_string());
        }
    }
}