# sc-risk-analyzer

`sc-risk-analyzer` is an experimental Rust-based static security analyzer for
Solidity smart contracts. It reports risk severity, confidence, supporting
evidence, and machine-readable SARIF for CI integration.

> **Prototype status:** This project is a research prototype, not a substitute
> for a professional security audit. Its findings are heuristic and may include
> false positives or false negatives.

## Capabilities

- Static analysis without deploying or executing a contract
- Rule-based checks for common Solidity security risks
- Lightweight interprocedural analysis across internal function calls
- Severity, confidence, and risk scoring
- JSON, text, and SARIF 2.1.0 output
- Severity filtering and CI-friendly failure behavior

The current rules cover:

- unsafe use of `tx.origin`
- `delegatecall`, low-level calls, and value-transferring external calls
- same-function and cross-function reentrancy indicators
- missing access-control indicators
- `selfdestruct`
- unchecked ERC-20 transfer indicators
- suspicious `TODO` and `FIXME` comments

## Current interprocedural analysis

The prototype implements a lightweight, heuristic form of interprocedural
analysis:

1. **Call-graph construction:** function declarations are indexed and internal
   or statically resolvable calls become graph edges. Ambiguous calls may create
   candidate edges; unresolved member and dynamic calls are retained as call
   sites but are not fully resolved.
2. **Local function summaries:** each function is summarized for external-call
   behavior, value transfer, state updates, and approximate storage-slot reads
   and writes.
3. **Cross-function propagation:** summary properties are propagated through
   reachable call-graph edges until no summary changes.
4. **Cross-function reentrancy detection:** public or external entry points are
   examined for reachable external calls and subsequent state updates. A
   storage-slot overlap check is used as a precision gate.
5. **Evidence generation:** a reported call-chain finding contains source-line
   evidence for the reachable external call and state update. This is evidence
   from reachable functions, not yet a complete executable path proof.

These capabilities distinguish the prototype from a purely line-by-line rule
scanner, while leaving significant research work in soundness, precision, and
semantic coverage.

## Install and build

Install the current stable Rust toolchain, clone the repository, and run:

```bash
cargo build
cargo test
```

## Usage

Analyze a Solidity file and print JSON (the default):

```bash
cargo run -- examples/Vulnerable.sol
```

Select text or SARIF output:

```bash
cargo run -- examples/Vulnerable.sol --format text
cargo run -- examples/Vulnerable.sol --format sarif --out result.sarif
```

Filter findings or make CI fail when findings are present:

```bash
cargo run -- examples/Vulnerable.sol --min-severity high --format text
cargo run -- examples/Vulnerable.sol --fail-on-findings
```

Useful environment variables:

- `SC_ANALYZER_DEBUG=1` prints call-graph and summary counts.
- `SC_STRICT_VALUE_ONLY=1` limits graph-based cross-function reentrancy reports
  to witnesses that appear to transfer value.

## Output and CI integration

JSON and text reports include the analyzed file, findings, and a summary. SARIF
output can be consumed by GitHub security and other SARIF-compatible tools. The
included GitHub Actions workflow builds and tests the project on pushes and pull
requests.

`--fail-on-findings` exits with status 1 when any finding remains after severity
filtering, allowing the analyzer to act as a CI gate.

## Current limitations

- Solidity source is scanned with lightweight custom parsing rather than a full
  compiler-derived abstract syntax tree and type system.
- Storage reads and writes are approximated from source text; aliasing, structs,
  inheritance, modifiers, inline assembly, and complex expressions are not
  modeled completely.
- Overloads, library calls, external dependencies, interfaces, function
  pointers, and dynamic dispatch may be unresolved or ambiguous.
- Summary propagation is not context-sensitive and does not model path
  conditions, transaction state, or precise call ordering.
- Reentrancy evidence identifies reachable source locations but does not yet
  prove one feasible end-to-end vulnerability path.
- The rule set and confidence values require systematic calibration against
  labeled benchmarks and real-world contracts.
- Results have not yet been comprehensively benchmarked against established
  Solidity analyzers.

## Research roadmap

Planned R&D will investigate:

- context-sensitive call-graph and interprocedural analysis
- more precise state-dependency, alias, modifier, and inheritance modeling
- feasible witness-path construction with ordered call and state transitions
- cross-function and cross-contract reentrancy analysis
- principled false-positive reduction and confidence calibration
- benchmark validation against labeled vulnerability corpora and established
  analyzers
- performance and scalability evaluation on production-size codebases
- stable CI integrations, rule authoring, and explainable reports

These items are research goals and should not be interpreted as features already
implemented in the current prototype.

## Commercialization direction

Potential commercialization through **Blockchain Wizard**, a Michigan LLC,
could use an open-core, hosted, or enterprise model. Candidate offerings include
managed scanning, private-repository support, dashboards, organization policies,
proprietary advanced rules, IDE and CI integrations, audit workflows, and
commercial support. Customer discovery and competitive validation are still
needed before selecting a final model.

## License

No software license is included in this repository at present. Publicly visible
source code is not automatically open source. A license should be selected only
after deciding which code, rules, and future capabilities will remain open and
which may support commercialization.

## Responsible use

Use this tool only on code you own or are authorized to assess. Independently
verify every finding before making security or deployment decisions.

Use this tool only on code you own or are authorized to assess. Independently
verify every finding before making security or deployment decisions.
