use std::collections::HashMap;

use crate::analysis::callgraph::CallGraph;
use crate::analysis::symbols::FunctionId;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FnSummary {
    pub has_external_call: bool,
    pub has_state_update: bool,
    pub sends_value: bool,
}

pub type SummaryMap = HashMap<FunctionId, FnSummary>;

pub fn compute_local_summaries(
    callgraph: &CallGraph,
    bodies: &HashMap<FunctionId, String>,
) -> SummaryMap {
    let mut summaries: SummaryMap = HashMap::new();

    for f in &callgraph.nodes {
        summaries.insert(f.clone(), FnSummary::default());
    }

    // external call / sends value from callsites
    for cs in &callgraph.callsites {
        let entry = summaries.entry(cs.caller.clone()).or_default();
        let raw = cs.raw.to_lowercase();

        // Recognize low-level calls whether extracted as ".call(" or "call(" or "call{"
        let is_low_level =
            raw.contains("delegatecall(")
            || raw.contains(".delegatecall(")
            || raw.contains("staticcall(")
            || raw.contains(".staticcall(")
            || raw.contains("call(")
            || raw.contains(".call(")
            || raw.contains("call{")     // catches call{value: ...}
            || raw.contains(".call{")
            || raw.contains("send(")
            || raw.contains(".send(")
            || raw.contains("transfer(")
            || raw.contains(".transfer(");

        if is_low_level {
            entry.has_external_call = true;
        }

        // value transfer signals
        if raw.contains("value")
            || raw.contains("send(") || raw.contains(".send(")
            || raw.contains("transfer(") || raw.contains(".transfer(")
        {
            // If it indicates value movement, treat as value send
            entry.sends_value = true;
        }
    }

    // state update from bodies (heuristic)
    for (fid, body) in bodies {
    let entry = summaries.entry(fid.clone()).or_default();
    let b = body.as_str();

        // external call from body
        if b.contains(".call{") || b.contains(".call(")
            || b.contains(".delegatecall(")
            || b.contains(".staticcall(")
            || b.contains(".send(")
            || b.contains(".transfer(")
        {
            entry.has_external_call = true;
        }

        if b.contains(".call{value") || b.contains("call{value")
            || b.contains(".send(") || b.contains(".transfer(")
        {
            entry.sends_value = true;
        }

        // state update
        if b.contains("+=")
            || b.contains("-=")
            || b.contains("++")
            || b.contains("--")
            || b.contains("balances[")
            || b.contains("mapping(")
        {
            entry.has_state_update = true;
        }
    }

    summaries
}

pub fn propagate_summaries(callgraph: &CallGraph, summaries: &mut SummaryMap) {
    let mut changed = true;

    while changed {
        changed = false;

        for (i, caller) in callgraph.nodes.iter().enumerate() {
            let caller_sum = summaries.get(caller).cloned().unwrap_or_default();

            let mut merged = caller_sum.clone();

            for edge in &callgraph.adj[i] {
                let callee = &callgraph.nodes[edge.to];
                let callee_sum = summaries.get(callee).cloned().unwrap_or_default();

                merged.has_external_call |= callee_sum.has_external_call;
                merged.has_state_update |= callee_sum.has_state_update;
                merged.sends_value |= callee_sum.sends_value;
            }

            if merged != caller_sum {
                summaries.insert(caller.clone(), merged);
                changed = true;
            }
        }
    }
}