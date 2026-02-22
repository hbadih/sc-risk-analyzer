use std::collections::HashMap;

use crate::analysis::callsites::{CallSite, CallTarget};
use crate::analysis::symbols::FunctionId;


#[derive(Debug, Clone, Copy)]
pub enum Certainty {
    Certain,
    Possible, // overload / ambiguous
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub to: usize,
    pub certainty: Certainty,
    pub callsite_span: (usize, usize),
}

#[derive(Debug, Default)]
pub struct CallGraph {
    pub nodes: Vec<FunctionId>,
    pub index: HashMap<FunctionId, usize>,
    pub adj: Vec<Vec<Edge>>,
    pub callsites: Vec<CallSite>, // keep for reporting/debug
}

impl CallGraph {
    pub fn ensure_node(&mut self, f: &FunctionId) -> usize {
        if let Some(&i) = self.index.get(f) {
            return i;
        }
        let i = self.nodes.len();
        self.nodes.push(f.clone());
        self.index.insert(f.clone(), i);
        self.adj.push(Vec::new());
        i
    }

    pub fn add_callsites(&mut self, cs: Vec<CallSite>) {
        for c in cs {
            let from = self.ensure_node(&c.caller);

            match &c.target {
                CallTarget::Direct(fid) => {
                    let to = self.ensure_node(fid);
                    self.adj[from].push(Edge {
                        to,
                        certainty: Certainty::Certain,
                        callsite_span: c.span,
                    });
                }
                CallTarget::Candidates(cands) => {
                    for fid in cands {
                        let to = self.ensure_node(fid);
                        self.adj[from].push(Edge {
                            to,
                            certainty: Certainty::Possible,
                            callsite_span: c.span,
                        });
                    }
                }
                CallTarget::Unresolved { .. } => {
                    // no edge, but keep callsite stored for later refinement
                }
            }

            self.callsites.push(c);
        }
    }
}