use crate::{ubold, RuleId, TidbId};
use ansi_term::Style;
use anyhow::{anyhow, Context, Result};
use flate2::read::GzDecoder;
use glob::glob;
use log::info;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;
use std::{fs::File, io::BufReader};

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TiKind {
    Ip,
    Url,
    Token,
    Regex,
}

impl Default for TiKind {
    fn default() -> Self {
        TiKind::Ip
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TiRules {
    rule_id: RuleId,
    name: String,
    description: Option<String>,
    references: Option<Vec<String>>,
    samples: Option<Vec<String>>,
    signatures: Option<Vec<String>>,
}

impl fmt::Display for TiRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Name: {}\nDescription:\n\t{:?}\nReferences:\n\t{:?}",
            ubold!(&self.name),
            self.description,
            self.references
        )?;
        if let Some(samples) = &self.samples {
            writeln!(f, "Samples:")?;
            for s in samples {
                writeln!(f, "\t{}", s)?;
            }
        }

        writeln!(f, "Signatures:\n\t{:?}", self.signatures)
    }
}

impl TiRules {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ComplexRules {
    pub id: TidbId,
    pub name: String,
    description: Option<String>,
    kind: TiKind,
    pub version: String,
    patterns: Vec<TiRules>,
}

impl ComplexRules {
    /// # Errors
    ///
    /// * fail to open file
    /// * invalid json format in file
    pub fn from_aice(path: &str) -> Result<Self> {
        let file = File::open(&path)?;
        let decoder = GzDecoder::new(file);
        let mut buf = Vec::new();
        let mut reader = BufReader::new(decoder);
        reader.read_to_end(&mut buf)?;
        bincode::deserialize(&buf).with_context(|| format!("cannot open {}", path))
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> TidbId {
        self.id
    }

    pub fn new(path: &str) -> Result<Vec<Self>> {
        let mut tidbs = Vec::new();
        for file in files_from(path)? {
            info!("loading {}", file);
            match ComplexRules::from_aice(&file) {
                Ok(x) => tidbs.push(x),
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Ok(tidbs)
    }

    pub fn get_label_name(&self, tidb_id: TidbId, rule_id: RuleId) -> Option<&str> {
        if tidb_id == self.id {
            if let Some(x) = self.patterns.iter().find(|p| p.rule_id == rule_id) {
                return Some(x.name());
            }
            return Some(&self.name);
        }
        None
    }
}

/// # Errors
///
/// Will return `Err` if a path cannot be read to determine if its contents match the glob pattern.
/// This is possible if the program lacks the appropriate permissions, for example.
fn files_from(name: &str) -> Result<Vec<String>> {
    let mut files: Vec<String> = Vec::new();
    for p in glob(name).unwrap().filter_map(Result::ok) {
        let filepath = p
            .to_str()
            .ok_or_else(|| anyhow!("invalid path"))?
            .to_string();
        files.push(filepath);
    }
    Ok(files)
}
