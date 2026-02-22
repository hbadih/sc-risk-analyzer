#![allow(warnings)]
use crate::analyzer::analyze;
use crate::analyzer::{filter_findings, print_text_report, summarize};
use clap::{Parser, ValueEnum};
use sc_risk_analyzer::analyzer;
use sc_risk_analyzer::models::{OutputFormat, Report, Severity};
use sc_risk_analyzer::utils::write_output;
use std::{fs, path::PathBuf};
use sc_risk_analyzer::models::Finding;

/// Static Smart-Contract Risk Analyzer (MVP)
#[derive(Parser, Debug)]
#[command(
    name = "sc_risk_analyzer",
    about = "Static Smart-Contract Risk Analyzer"
)]

struct Args {
    /// Path to Solidity (.sol) file
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Output format: json | text | sarif
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Write output to file instead of stdout
    #[arg(long)]
    out: Option<PathBuf>,

    /// Minimum severity to report: low | medium | high
    #[arg(long, value_enum, default_value_t = Severity::Low)]
    min_severity: Severity,

    /// Fail (exit code 2) if any finding severity is >= this level (CI gate)
    #[arg(long, value_enum)]
    fail_on: Option<Severity>,

    /// Exit with code 1 if findings are present (useful for CI)
    #[arg(long, default_value_t = false)]
    fail_on_findings: bool,
}

fn should_fail(findings: &[Finding], threshold: Severity) -> bool {
    let thr = threshold.rank();
    findings.iter().any(|f| f.severity.rank() >= thr)
}
/// ---- main ----

fn main() {
    let args = Args::parse();

    let code = fs::read_to_string(&args.file).expect("Failed to read Solidity file");

    let findings = analyze(&code);
    let findings = filter_findings(findings, args.min_severity);
    let summary = summarize(&findings);

    let report = Report {
        file: args.file.to_string_lossy().to_string(),
        findings,
        summary,
    };

    match args.format {
        OutputFormat::Text => {
            print_text_report(&report.file, &report.findings, &report.summary);
        }
        OutputFormat::Sarif => {
            let sarif_log = sc_risk_analyzer::sarif::to_sarif(&report.file, &report.findings);
            let text = serde_json::to_string_pretty(&sarif_log).unwrap();
            write_output(&args.out, &text);
        }
        OutputFormat::Json => {
            let text = serde_json::to_string_pretty(&report).unwrap();
            write_output(&args.out, &text);
        }
    }

    // CI behavior
    if args.fail_on_findings && report.summary.total > 0 {
        eprintln!(
            "Findings detected (min severity: {}). Exiting with code 1.",
            args.min_severity.as_str()
        );
        std::process::exit(1);
    }
}
