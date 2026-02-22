# sc-risk-analyzer

A Rust-based static security analyzer for Solidity smart contracts with
risk scoring, confidence estimation, and SARIF output for CI integration.

---

## 🔍 Overview

**sc-risk-analyzer** is a lightweight static analysis tool that scans Solidity
smart contracts for common security risks such as:

- Unsafe authorization (`tx.origin`)
- Reentrancy patterns
- Low-level external calls
- Missing access control
- Suspicious TODO/FIXME comments

The tool is designed for **security auditing**, **CI pipelines**, and
**research experimentation**, producing both human-readable and
machine-consumable (SARIF) reports.

---

## ✨ Features

- Written in **Rust** for performance and safety
- Static analysis (no blockchain execution required)
- Risk scoring with confidence levels
- Multiple output formats:
  - JSON
  - Text
  - SARIF (for GitHub Security / CI tools)
- CI-friendly (`--fail-on-findings` support)
- Extensible rule-based architecture

---

## 🚀 Usage

### Analyze a Solidity file

```bash
cargo run -- examples/Vulnerable.sol
cargo run -- examples/Vulnerable.sol --format text
cargo run -- examples/Vulnerable.sol --format sarif
File: examples/Vulnerable.sol
Summary: total=5 high=3 medium=1 low=1 max_risk=9.5

[High] TX_ORIGIN (risk=9.5 conf=0.95) @ line 29
  Use of tx.origin for authorization is unsafe
examples/Vulnerable.sol