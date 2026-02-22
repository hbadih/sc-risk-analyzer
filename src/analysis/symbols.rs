use std::collections::HashMap;

/// Identify a contract uniquely.
/// If you have multi-file projects, add a file_id/path field later.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContractId {
    pub name: String,
}

/// Identify a function uniquely (supports overloads).
/// `sig_key` should be stable: e.g., "transfer(address,uint256)" or a hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionId {
    pub contract: ContractId,
    pub sig_key: String,
    pub display_name: String, // friendly for printing
}

/// A minimal function “header” record that SymbolIndex will index.
/// You can populate this from your ContextMap without changing it.
#[derive(Debug, Clone)]
pub struct FnDecl {
    pub contract_name: String,
    pub display_name: String, // e.g., "transfer"
    pub sig_key: String,      // e.g., "transfer(address,uint256)" or "transfer#2"
}

/// Symbol index: resolves internal and library/static calls quickly.
#[derive(Debug, Default)]
pub struct SymbolIndex {
    /// contract name -> ContractId
    pub contracts: HashMap<String, ContractId>,
    /// (contract name, function name) -> candidate FunctionIds (overloads)
    pub by_contract_and_name: HashMap<(String, String), Vec<FunctionId>>,
    /// (contract name, sig_key) -> exact FunctionId
    pub by_contract_and_sig: HashMap<(String, String), FunctionId>,
}

impl SymbolIndex {
    pub fn from_decls(decls: impl IntoIterator<Item = FnDecl>) -> Self {
        let mut idx = SymbolIndex::default();

        for d in decls {
            let c = idx
                .contracts
                .entry(d.contract_name.clone())
                .or_insert_with(|| ContractId {
                    name: d.contract_name.clone(),
                })
                .clone();

            let fid = FunctionId {
                contract: c.clone(),
                sig_key: d.sig_key.clone(),
                display_name: format!("{}::{}", c.name, d.display_name),
            };

            idx.by_contract_and_sig
                .insert((c.name.clone(), d.sig_key.clone()), fid.clone());

            idx.by_contract_and_name
                .entry((c.name.clone(), d.display_name.clone()))
                .or_default()
                .push(fid);
        }

        idx
    }

    /// Resolve an internal call `foo()` within a specific contract.
    pub fn resolve_internal_by_name(&self, contract_name: &str, fn_name: &str) -> Vec<FunctionId> {
        self.by_contract_and_name
            .get(&(contract_name.to_string(), fn_name.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// Resolve a static/library call `Lib.foo()` if `Lib` is a known contract/library name.
    pub fn resolve_static_by_name(&self, lib_or_contract: &str, fn_name: &str) -> Vec<FunctionId> {
        self.resolve_internal_by_name(lib_or_contract, fn_name)
    }
}