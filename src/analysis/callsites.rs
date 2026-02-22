use crate::analysis::symbols::{FunctionId, SymbolIndex};

#[derive(Debug, Clone)]
pub struct CallSite {
    pub caller: FunctionId,
    pub span: (usize, usize), // byte offsets in the function body string
    pub raw: String,
    pub kind: CallKind,
    pub target: CallTarget,
}

#[derive(Debug, Clone)]
pub enum CallKind {
    Internal,        // foo()
    LibraryStatic,   // Lib.foo()
    ExternalMember,  // x.foo() (unresolved for now)
    LowLevel,        // addr.call / delegatecall / send / transfer / staticcall
}

#[derive(Debug, Clone)]
pub enum CallTarget {
    Direct(FunctionId),
    Candidates(Vec<FunctionId>),
    Unresolved { hint: String },
}

/// Very lightweight scanner:
/// - Finds patterns like foo(, Lib.foo(, x.foo(
/// - Detects low-level calls by substring
pub fn extract_callsites(
    contract_name: &str,
    caller: &FunctionId,
    fn_body: &str,
    symbols: &SymbolIndex,
) -> Vec<CallSite> {
    let mut out = Vec::new();

    // 1) low-level calls (easy wins)
    for (needle, label) in [
        (".delegatecall(", "delegatecall"),
        (".staticcall(", "staticcall"),
        (".call(", "call"),
        (".send(", "send"),
        (".transfer(", "transfer"),
    ] {
        let mut start = 0;
        while let Some(pos) = fn_body[start..].find(needle) {
            let abs = start + pos;
            let end = (abs + needle.len()).min(fn_body.len());
            out.push(CallSite {
                caller: caller.clone(),
                span: (abs, end),
                raw: fn_body[abs..end].to_string(),
                kind: CallKind::LowLevel,
                target: CallTarget::Unresolved {
                    hint: label.to_string(),
                },
            });
            start = end;
        }
    }

    // 2) heuristic parse for identifiers before '(' and optional `A.B(`
    //
    // We scan for '(' then look backwards to capture an identifier or dotted identifier.
    // This avoids regex dependencies and keeps it fast.
    for (i, ch) in fn_body.bytes().enumerate() {
        if ch != b'(' {
            continue;
        }

        // walk backward skipping spaces
        let mut j = i;
        while j > 0 && fn_body.as_bytes()[j - 1].is_ascii_whitespace() {
            j -= 1;
        }

        // capture token chunk ending at j: could be "foo" or "A.foo" or "x.foo"
        let mut k = j;
        while k > 0 {
            let b = fn_body.as_bytes()[k - 1];
            let ok = b.is_ascii_alphanumeric() || b == b'_' || b == b'.';
            if !ok {
                break;
            }
            k -= 1;
        }

        if k == j {
            continue;
        }

        let token = &fn_body[k..j];

        // Ignore keywords that look like calls
        if matches!(token, "if" | "for" | "while" | "return" | "require" | "assert") {
            continue;
        }

        // token forms:
        // - foo
        // - A.foo
        // - x.foo
        if let Some((left, right)) = token.rsplit_once('.') {
            // A.foo(  OR x.foo(
            let fn_name = right;

            // If left is a known contract/library name, resolve as static/library call
            let candidates = symbols.resolve_static_by_name(left, fn_name);
            if !candidates.is_empty() {
                out.push(CallSite {
                    caller: caller.clone(),
                    span: (k, i + 1),
                    raw: format!("{}(", token),
                    kind: CallKind::LibraryStatic,
                    target: if candidates.len() == 1 {
                        CallTarget::Direct(candidates[0].clone())
                    } else {
                        CallTarget::Candidates(candidates)
                    },
                });
            } else {
                // otherwise treat as member call unresolved for now
                out.push(CallSite {
                    caller: caller.clone(),
                    span: (k, i + 1),
                    raw: format!("{}(", token),
                    kind: CallKind::ExternalMember,
                    target: CallTarget::Unresolved {
                        hint: format!("{}.{}", left, fn_name),
                    },
                });
            }
        } else {
            // foo(
            let fn_name = token;
            let candidates = symbols.resolve_internal_by_name(contract_name, fn_name);
            if candidates.is_empty() {
                // Could be built-in / local function / unresolved
                out.push(CallSite {
                    caller: caller.clone(),
                    span: (k, i + 1),
                    raw: format!("{}(", token),
                    kind: CallKind::Internal,
                    target: CallTarget::Unresolved {
                        hint: fn_name.to_string(),
                    },
                });
            } else {
                out.push(CallSite {
                    caller: caller.clone(),
                    span: (k, i + 1),
                    raw: format!("{}(", token),
                    kind: CallKind::Internal,
                    target: if candidates.len() == 1 {
                        CallTarget::Direct(candidates[0].clone())
                    } else {
                        CallTarget::Candidates(candidates)
                    },
                });
            }
        }
    }

    out
}