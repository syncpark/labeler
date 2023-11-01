use crate::EventType;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader, path::Path};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ColumnType {
    Datetime,
    Enum,
    Float64,
    Int64,
    Ipaddr,
    Utf8,
    Binary,
}

pub trait Load
where
    for<'de> Self: Deserialize<'de> + Sized,
{
    /// # Errors
    ///
    /// Will return `Err` if file not found or no permission or json syntax error
    fn from_path<P: AsRef<Path> + std::fmt::Display>(path: P) -> Result<Self> {
        let file = File::open(&path)?;
        serde_json::from_reader(BufReader::new(file))
            .with_context(|| format!("cannot open {}", &path))
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    event_type: EventType,
    time_column: usize,
    format: Vec<ColumnFormat>,
    input_log: String,
    input_clusters: String,
    input_labels: String,
    tidb: String, // directory name
    #[serde(default = "default_keycolumn")]
    key_column: String, // must match alias field name
    #[serde(default = "default_delimiter")]
    delimiter: char,
}

fn default_delimiter() -> char {
    ','
}

fn default_keycolumn() -> String {
    "uid".to_string()
}

#[derive(Debug, Deserialize)]
struct ColumnFormat {
    data_type: ColumnType,
    #[serde(default = "Default::default")]
    weight: f64,
    format: Option<String>,
    alias: String,
}

impl Config {
    #[must_use]
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    #[must_use]
    pub fn clusters(&self) -> &str {
        &self.input_clusters
    }

    #[must_use]
    pub fn column_len(&self) -> usize {
        self.format.len()
    }

    #[must_use]
    pub fn delimiter(&self) -> char {
        self.delimiter
    }

    #[must_use]
    pub fn events(&self) -> &str {
        &self.input_log
    }

    #[must_use]
    pub fn features(&self) -> Vec<usize> {
        self.format
            .iter()
            .enumerate()
            .filter_map(|(idx, col)| {
                if col.weight > 0.0 {
                    return Some(idx);
                }

                None
            })
            .collect()
    }

    #[must_use]
    pub fn key_field(&self) -> Option<usize> {
        self.format
            .iter()
            .position(|column| column.alias == self.key_column)
    }

    #[must_use]
    pub fn time_format(&self) -> Option<&str> {
        self.format.get(self.time_column).and_then(|c| {
            if c.data_type == ColumnType::Datetime {
                c.format.as_deref()
            } else {
                None
            }
        })
    }

    #[must_use]
    pub fn labels(&self) -> &str {
        &self.input_labels
    }

    #[must_use]
    pub fn tidb(&self) -> &str {
        &self.tidb
    }
}

impl Load for Config {}

impl Config {
    /// # Panics
    /// * if config file has invalid json format
    #[must_use]
    pub fn init(config_path: &str) -> Self {
        match Config::from_path(config_path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("{:?}", e);
                std::process::exit(-1);
            }
        }
    }
}
