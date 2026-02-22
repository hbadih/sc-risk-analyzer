use crate::models::Severity;
use std::{fs, path::PathBuf};

/// Find first line containing `pattern` (simple MVP matching)
pub fn first_match(code: &str, pattern: &str) -> Option<(usize, String)> {
    for (i, line) in code.lines().enumerate() {
        if line.contains(pattern) {
            return Some((i + 1, line.trim().to_string()));
        }
    }
    None
}

/// Find all matches for a pattern (for rules that might report multiple findings)
pub fn all_matches(code: &str, pattern: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in code.lines().enumerate() {
        if line.contains(pattern) {
            out.push((i + 1, line.trim().to_string()));
        }
    }
    out
}

/// Find first line containing ANY of the patterns
pub fn first_match_any(code: &str, patterns: &[&str]) -> Option<(usize, String)> {
    for (i, line) in code.lines().enumerate() {
        let s = line.trim();
        for &pat in patterns {
            if s.contains(pat) {
                return Some((i + 1, s.to_string()));
            }
        }
    }
    None
}
pub fn write_output(out: &Option<PathBuf>, text: &str) {
    if let Some(path) = out {
        fs::write(path, text).expect("Failed to write output file");
    } else {
        println!("{}", text);
    }
}

pub fn compute_risk(sev: Severity, confidence: f32) -> f32 {
    let c = confidence.clamp(0.0, 1.0);
    let score = 10.0 * severity_weight(sev) * c; // 0..10
    (score * 10.0).round() / 10.0 // 1 decimal
}

/// Risk model (0..10)
fn severity_weight(sev: Severity) -> f32 {
    match sev {
        Severity::High => 1.0,
        Severity::Medium => 0.6,
        Severity::Low => 0.3,
    }
}

pub fn round2(x: f32) -> f32 {
    (x * 100.0).round() / 100.0
}

/// Return (start_line_of_block, block_text) for each function block
pub fn split_functions_with_start_lines(code: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        if lines[i].contains("function ") {
            let start_line = i + 1;
            let mut block = Vec::new();
            block.push(lines[i]);

            i += 1;
            while i < lines.len() && !lines[i].contains("function ") {
                block.push(lines[i]);
                i += 1;
            }

            out.push((start_line, block.join("\n")));
        } else {
            i += 1;
        }
    }

    out
}

pub fn build_context_map(code: &str) -> Vec<(Option<String>, Option<String>)> {
    let mut map: Vec<(Option<String>, Option<String>)> = Vec::new();

    let mut current_contract: Option<String> = None;
    let mut current_function: Option<String> = None;

    // Track whether we are inside a contract/interface/library body
    let mut scope_depth: i32 = 0;
    let mut in_contract_scope: bool = false;

    for line in code.lines() {
        let trimmed = line.trim();

        // Detect start of a new contract/interface/library declaration
        if let Some(name) = parse_name_after_keyword(trimmed, "contract")
            .or_else(|| parse_name_after_keyword(trimmed, "interface"))
            .or_else(|| parse_name_after_keyword(trimmed, "library"))
        {
            current_contract = Some(name);
            current_function = None; // reset function
            // We haven't entered the body yet; wait until we see '{'
            in_contract_scope = false;
        }

        // If we see '{' after a contract/interface/library, we enter contract scope
        // We update depth BEFORE function detection so function lines inside same line work.
        for ch in trimmed.chars() {
            if ch == '{' {
                scope_depth += 1;
                if current_contract.is_some() {
                    in_contract_scope = true;
                }
            } else if ch == '}' {
                scope_depth -= 1;
                if scope_depth <= 0 {
                    // We left the current top-level scope
                    scope_depth = 0;
                    in_contract_scope = false;
                    current_function = None; // leaving contract scope clears function
                }
            }
        }

        // Detect function ONLY if we're inside a contract/interface/library scope
        if in_contract_scope {
            if let Some(name) = parse_name_after_keyword(trimmed, "function") {
                current_function = Some(name);
            }
        }

        let (c, f) = if in_contract_scope {
            (current_contract.clone(), current_function.clone())
        } else {
            (None, None)
        };

        map.push((c, f));
    }

    map
}

fn parse_name_after_keyword(line: &str, keyword: &str) -> Option<String> {
    // Works even if the line is:
    // "abstract contract X is Y {"
    // "contract X {"
    // "function withdraw(uint a) external {"
    // "function withdrawAll() external {"
    let s = line.trim();

    // Split into tokens
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let mut i = 0;

    while i < tokens.len() {
        if tokens[i] == keyword {
            // next token should be the name
            if i + 1 < tokens.len() {
                let mut name = tokens[i + 1].to_string();

                // For function: "withdrawAll()" -> "withdrawAll"
                if let Some(pos) = name.find('(') {
                    name.truncate(pos);
                }

                // For contract/interface/library: "X{" or "X{" forms
                name = name.trim_end_matches('{').to_string();

                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
        i += 1;
    }

    None
}
