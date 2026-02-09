use clap::Parser;
use serde::Serialize;
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "sc_risk_analyzer", about = "Static Smart-Contract Risk Analyzer")]
struct Args {
    /// Path to Solidity (.sol) file
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Output format: json or text
    #[arg(long, default_value = "json")]
    format: String,

    /// Write output to file instead of stdout
    #[arg(long)]
    out: Option<PathBuf>,

    /// Minimum severity to report: low, medium, high
    #[arg(long, default_value = "low")]
    min_severity: String,

    /// Exit with code 1 if findings are present (useful for CI)
    #[arg(long, default_value_t = false)]
    fail_on_findings: bool,

}



#[derive(Serialize, Debug, Clone)]
enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Serialize)]
struct Finding {
    rule: String,
    severity: Severity,
    description: String,
    line: Option<usize>,
    evidence: String,

    confidence: f32,  // 0.0 to 1.0
    risk_score: f32,  // 0.0 to 10.0
}


#[derive(Serialize)]
struct Report {
    file: String,
    findings: Vec<Finding>,
    summary: Summary,
}

#[derive(Serialize)]
struct Summary {
    total: usize,
    high: usize,
    medium: usize,
    low: usize,
    max_risk: f32,
}

#[derive(Serialize)]
struct SarifLog {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifDriver {
    name: String,
    informationUri: String,
    rules: Vec<SarifRule>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    shortDescription: SarifMessage,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifResult {
    ruleId: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifProperties,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifProperties {
    confidence: f32,
    risk_score: f32,
    severity: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifLocation {
    physicalLocation: SarifPhysicalLocation,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifPhysicalLocation {
    artifactLocation: SarifArtifactLocation,
    region: SarifRegion,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifRegion {
    startLine: usize,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

fn summarize(findings: &[Finding]) -> Summary {
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut max_risk = 0.0;

    for f in findings {
        match f.severity {
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
        if f.risk_score > max_risk {
            max_risk = f.risk_score;
        }
    }

    Summary {
        total: findings.len(),
        high,
        medium,
        low,
        max_risk,
    }
}

fn parse_min_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn severity_rank(sev: &Severity) -> u8 {
    match sev {
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

fn filter_findings(findings: Vec<Finding>, min_sev: &Severity) -> Vec<Finding> {
    let min_rank = severity_rank(min_sev);
    findings
        .into_iter()
        .filter(|f| severity_rank(&f.severity) >= min_rank)
        .collect()
}

fn print_text_report(file: &str, findings: &[Finding], summary: &Summary) {
    println!("File: {}", file);
    println!(
        "Summary: total={} high={} medium={} low={} max_risk={}",
        summary.total, summary.high, summary.medium, summary.low, summary.max_risk
    );
    println!();

    for f in findings {
        let line_str = f.line.map(|n| n.to_string()).unwrap_or("-".to_string());
        println!(
            "[{:?}] {} (risk={} conf={}) @ line {}",
            f.severity, f.rule, f.risk_score, f.confidence, line_str
        );
        println!("  {}", f.description);
        println!("  evidence: {}", f.evidence);
        println!();
    }
}

fn sarif_level_from_severity(sev: &Severity) -> String {
    match sev {
        Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low => "note".to_string(),
    }
}

fn to_sarif(file: &str, findings: &[Finding]) -> SarifLog {
    // Build rules list (unique per rule id)
    let mut rules: Vec<SarifRule> = Vec::new();
    for f in findings {
        if !rules.iter().any(|r| r.id == f.rule) {
            rules.push(SarifRule {
                id: f.rule.clone(),
                name: f.rule.clone(),
                shortDescription: SarifMessage {
                    text: f.description.clone(),
                },
            });
        }
    }

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| SarifResult {
            ruleId: f.rule.clone(),
            level: sarif_level_from_severity(&f.severity),
            message: SarifMessage {
                text: format!("{} | evidence: {}", f.description, f.evidence),
            },
            locations: vec![SarifLocation {
                physicalLocation: SarifPhysicalLocation {
                    artifactLocation: SarifArtifactLocation {
                        uri: file.to_string(),
                    },
                    region: SarifRegion {
                        startLine: f.line.unwrap_or(1),
                    },
                },
            }],
            properties: SarifProperties {
                confidence: f.confidence,
                risk_score: f.risk_score,
                severity: format!("{:?}", f.severity),
            },
        })
        .collect();

    SarifLog {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sc_risk_analyzer".to_string(),
                    informationUri: "https://example.com/sc_risk_analyzer".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

fn write_output(out: &Option<PathBuf>, text: &str) {
    if let Some(path) = out {
        std::fs::write(path, text).expect("Failed to write output file");
    } else {
        println!("{}", text);
    }
}

fn main() {
    let args = Args::parse();

    let code = fs::read_to_string(&args.file)
        .expect("Failed to read Solidity file");

    let findings = analyze(&code);

    let min_sev = parse_min_severity(&args.min_severity);
    let findings = filter_findings(findings, &min_sev);

    let summary = summarize(&findings);

    let report = Report {
        file: args.file.to_string_lossy().to_string(),
        findings,
        summary,
    };

    let fmt = args.format.to_lowercase();

    if fmt == "text" {
        print_text_report(&report.file, &report.findings, &report.summary);
    } else if fmt == "sarif" {
        let sarif = to_sarif(&report.file, &report.findings);
        let text = serde_json::to_string_pretty(&sarif).unwrap();
        write_output(&args.out, &text);
       // println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
    } else {
        let text = serde_json::to_string_pretty(&report).unwrap();
        write_output(&args.out, &text);
        //println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }


    // Exit code for CI: fail if any findings at/above min severity
    if args.fail_on_findings && report.summary.total > 0 {
        std::process::exit(1);
    }

}


fn analyze(code: &str) -> Vec<Finding> {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(TxOriginRule),
        Box::new(DelegatecallRule),
        Box::new(PayableExternalCallRule),
        Box::new(LowLevelCallRule),
        Box::new(ReentrancyHeuristicRule),
        Box::new(MissingAccessControlRule),
        Box::new(TodoCommentRule), // (new Low severity rule to remove your warning)
    ];

    let mut findings = Vec::new();
    for rule in rules {
        findings.extend(rule.check(code));
    }
    findings.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
    findings
}

trait Rule {
    fn id(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;
    fn check(&self, code: &str) -> Vec<Finding>;
}

fn severity_weight(sev: &Severity) -> f32 {
    match sev {
        Severity::High => 10.0,
        Severity::Medium => 6.0,
        Severity::Low => 3.0,
    }
}

fn compute_risk(sev: &Severity, confidence: f32) -> f32 {
    // clamp confidence to [0, 1]
    let c = confidence.clamp(0.0, 1.0);
    // risk score on a 0–10 scale
    (severity_weight(sev) * c * 10.0).round() / 10.0 // 1 decimal
}

fn first_match(code: &str, pattern: &str) -> Option<(usize, String)> {
    for (i, line) in code.lines().enumerate() {
        if line.contains(pattern) {
            return Some((i + 1, line.trim().to_string()));
        }
    }
    None
}

// ---- Rule 1: tx.origin ----
struct TxOriginRule;

impl Rule for TxOriginRule {
    fn id(&self) -> &'static str { "TX_ORIGIN" }
    fn severity(&self) -> Severity { Severity::High }
    fn description(&self) -> &'static str { "Use of tx.origin for authorization is unsafe" }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some((ln, ev)) = first_match(code, "tx.origin") {
            let confidence = 0.95;
            let sev = self.severity();
            let risk = compute_risk(&sev, confidence);

            out.push(Finding {
                rule: self.id().to_string(),
                severity: sev,
                description: self.description().to_string(),
                line: Some(ln),
                evidence: ev,
                confidence: 0.95,
                risk_score: risk,

            });

        }
        out
    }
}

// ---- Rule 2: delegatecall ----
struct DelegatecallRule;

impl Rule for DelegatecallRule {
    fn id(&self) -> &'static str { "DELEGATECALL" }
    fn severity(&self) -> Severity { Severity::High }
    fn description(&self) -> &'static str { "delegatecall can lead to storage collision and code injection" }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some((ln, ev)) = first_match(code, "delegatecall") {
            out.push(Finding {
                rule: self.id().to_string(),
                severity: self.severity(),
                description: self.description().to_string(),
                line: Some(ln),
                evidence: ev,
                confidence: 0.85,
                risk_score: compute_risk(&self.severity(), 0.85),

            });
        }
        out
    }
}

// ---- Rule 3: low-level call ----
struct LowLevelCallRule;

impl Rule for LowLevelCallRule {
    fn id(&self) -> &'static str { "LOW_LEVEL_CALL" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn description(&self) -> &'static str { "Low-level call detected; ensure return value is checked" }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let llc = first_match(code, ".call(")
            .or_else(|| {
                // Match call{...} but avoid call{value...} which is handled by PAYABLE_EXTERNAL_CALL
                let m = first_match(code, "call{");
                if let Some((_, ref ev)) = m {
                    if ev.contains("call{value") {
                        return None;
                    }
                }
                m
            });

        if let Some((ln, ev)) = llc {
            out.push(Finding {
                rule: self.id().to_string(),
                severity: self.severity(),
                description: self.description().to_string(),
                line: Some(ln),
                evidence: ev,
                confidence: 0.75,
                risk_score: compute_risk(&self.severity(), 0.75),
            });
        }
        out
    }
}

// ---- Rule 4 (LOW severity): TODO/FIXME comments ----
// This is a common lightweight "code smell" check and it will also remove your "Low never constructed" warning.
struct TodoCommentRule;

impl Rule for TodoCommentRule {
    fn id(&self) -> &'static str { "TODO_COMMENT" }
    fn severity(&self) -> Severity { Severity::Low }
    fn description(&self) -> &'static str { "TODO/FIXME comment found (potential unfinished security logic)" }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let todo = first_match(code, "TODO").or_else(|| first_match(code, "FIXME"));
        if let Some((ln, ev)) = todo {
            out.push(Finding {
                rule: self.id().to_string(),
                severity: self.severity(),
                description: self.description().to_string(),
                line: Some(ln),
                evidence: ev,
                confidence: 0.40,
                risk_score: compute_risk(&self.severity(), 0.40),
            });
        }
        out
    }
}

struct MissingAccessControlRule;

impl Rule for MissingAccessControlRule {
    fn id(&self) -> &'static str { "MISSING_ACCESS_CONTROL" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn description(&self) -> &'static str {
        "Sensitive function may be missing access control (heuristic)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // quick indicator of access control usage
        let has_ac = code.contains("onlyOwner")
            || code.contains("onlyRole")
            || code.contains("AccessControl")
            || code.contains("Ownable");

        // list of sensitive function name markers
        let sensitive = [
            "function withdrawAll",
            "function mint",
            "function burn",
            "function upgrade",
            "function setOwner",
            "function setAdmin",
            "function pause",
            "function unpause",
            "function withdraw", // keep generic ones last
            "function set",
        ];

        if has_ac {
            return out; // if access control exists somewhere, we won't flag this heuristic
        }

        for pat in sensitive {
            if let Some((ln, ev)) = first_match(code, pat) {
                out.push(Finding {
                    rule: self.id().to_string(),
                    severity: self.severity(),
                    description: self.description().to_string(),
                    line: Some(ln),
                    evidence: ev,
                    confidence: 0.60,
                    risk_score: compute_risk(&self.severity(), 0.60),
                });
                break; // avoid spamming; one finding is enough
            }
        }

        out
    }
}

struct ReentrancyHeuristicRule;

impl Rule for ReentrancyHeuristicRule {
    fn id(&self) -> &'static str { "REENTRANCY_HEURISTIC" }
    fn severity(&self) -> Severity { Severity::High }
    fn description(&self) -> &'static str {
        "Possible reentrancy risk: external call and state update in same function (heuristic)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // Very simple function-level heuristic:
        // Split by "function " blocks (not a real parser, but works for MVP).
        for block in code.split("function ").skip(1) {
            // take the header line (function signature) for evidence
            let header = block.lines().next().unwrap_or("").trim();
            let func_name_evidence = format!("function {}", header);

            let has_external_call =
                block.contains(".call{value") || block.contains("call{value") || block.contains(".call(");

            let has_state_update =
                block.contains("balances[msg.sender]") && (block.contains("-=") || block.contains("+="))
                || block.contains("-="); // broad, still useful

            if has_external_call && has_state_update {
                // Try to point to the line where external call occurs
                let call_ln = first_match(code, ".call{value")
                    .or_else(|| first_match(code, "call{value"))
                    .or_else(|| first_match(code, ".call("));

                let (line, evidence) = match call_ln {
                    Some((ln, ev)) => (Some(ln), ev),
                    None => (None, func_name_evidence.clone()),
                };

                out.push(Finding {
                    rule: self.id().to_string(),
                    severity: self.severity(),
                    description: self.description().to_string(),
                    line,
                    evidence,
                    confidence: 0.70,
                    risk_score: compute_risk(&self.severity(), 0.70),
                });

                break; // avoid spamming
            }
        }

        out
    }
}

struct PayableExternalCallRule;

impl Rule for PayableExternalCallRule {
    fn id(&self) -> &'static str { "PAYABLE_EXTERNAL_CALL" }
    fn severity(&self) -> Severity { Severity::High }
    fn description(&self) -> &'static str {
        "External call with value detected (reentrancy and fund-drain risk)"
    }

    fn check(&self, code: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // Detect `.call{value: ...}` patterns
        if let Some((ln, ev)) = first_match(code, ".call{value") {
            out.push(Finding {
                rule: self.id().to_string(),
                severity: self.severity(),
                description: self.description().to_string(),
                line: Some(ln),
                evidence: ev,
                confidence: 0.90,
                risk_score: compute_risk(&self.severity(), 0.90),
            });
        } else if let Some((ln, ev)) = first_match(code, "call{value") {
            out.push(Finding {
                rule: self.id().to_string(),
                severity: self.severity(),
                description: self.description().to_string(),
                line: Some(ln),
                evidence: ev,
                confidence: 0.90,
                risk_score: compute_risk(&self.severity(), 0.90),

            });
        }

        out
    }
}
