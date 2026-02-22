use clap::ValueEnum;
use serde::Serialize;

#[derive(ValueEnum, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Text,
    Sarif,
}

#[derive(ValueEnum, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct EvidenceItem {
    pub message: String,
    pub line: Option<usize>,
    pub snippet: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Evidence {
    pub summary: String,
    pub items: Vec<EvidenceItem>,
}

impl Evidence {
    pub fn single(summary: &str, message: &str, line: Option<usize>, snippet: String) -> Self {
        Self {
            summary: summary.to_string(),
            items: vec![EvidenceItem {
                message: message.to_string(),
                line,
                snippet,
            }],
        }
    }

    pub fn two_items(
        summary: &str,
        a_msg: &str,
        a_line: Option<usize>,
        a_snip: String,
        b_msg: &str,
        b_line: Option<usize>,
        b_snip: String,
    ) -> Self {
        Self {
            summary: summary.to_string(),
            items: vec![
                EvidenceItem {
                    message: a_msg.to_string(),
                    line: a_line,
                    snippet: a_snip,
                },
                EvidenceItem {
                    message: b_msg.to_string(),
                    line: b_line,
                    snippet: b_snip,
                },
            ],
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub description: String,
    // NEW: where in the code
    pub contract: Option<String>,
    pub function: Option<String>,

    pub line: Option<usize>,
    pub evidence: Evidence,
    pub confidence: f32,
    pub risk_score: f32,
}

#[derive(Serialize, Debug)]
pub struct Report {
    pub file: String,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

#[derive(Serialize, Debug)]
pub struct Summary {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub max_risk: f32,
}
