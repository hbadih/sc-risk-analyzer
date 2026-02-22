use crate::models::*;
use serde::Serialize;

#[derive(Serialize)]
pub struct SarifLog {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Serialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
}

#[derive(Serialize)]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub properties: SarifProperties,
}

#[derive(Serialize)]
pub struct SarifProperties {
    pub confidence: f32,
    pub risk_score: f32,
    pub severity: String,
}

#[derive(Serialize)]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Serialize)]
pub struct SarifRegion {
    pub start_line: usize,
}

#[derive(Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Serialize)]
pub struct SarifReportingDescriptor {
    #[serde(rename = "information_uri")]
    pub information_uri: String,

    #[serde(rename = "short_description")]
    pub short_description: SarifMessage,
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

pub fn to_sarif(file: &str, findings: &[Finding]) -> SarifLog {
    // Unique rules list (by rule id)
    let mut rules: Vec<SarifRule> = Vec::new();
    for f in findings {
        if !rules.iter().any(|r| r.id == f.rule) {
            rules.push(SarifRule {
                id: f.rule.clone(),
                name: f.rule.clone(),
                short_description: SarifMessage {
                    text: f.description.clone(),
                },
            });
        }
    }

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.rule.clone(),
            level: sarif_level(f.severity).to_string(),
            message: SarifMessage {
                text: format!("{} | evidence: {}", f.description, f.evidence.summary),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: file.to_string(),
                    },
                    region: SarifRegion {
                        start_line: f.line.unwrap_or(1),
                    },
                },
            }],
            properties: SarifProperties {
                confidence: f.confidence,
                risk_score: f.risk_score,
                severity: f.severity.as_str().to_string(),
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
                    information_uri: "https://example.com/sc_risk_analyzer".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}
