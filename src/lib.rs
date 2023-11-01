mod cluster;
pub mod config;
mod events;
mod labels;
pub mod matcher;
mod parser;
mod tidb;

use ansi_term::Colour;
use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use strum::EnumIter;

pub type ClusterId = usize;
pub type Score = f32;
pub type TidbId = u32;
pub type RuleId = u32;
pub type PatternId = (TidbId, RuleId);
pub type MessageId = String;
pub type TokensVector = Vec<(MessageId, Vec<String>, Vec<String>)>;

/* Datasource data type */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Csv,
    Log,
    Packet,
}

impl Default for EventType {
    fn default() -> Self {
        EventType::Csv
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Csv => write!(f, "csv"),
            EventType::Log => write!(f, "log"),
            EventType::Packet => write!(f, "packet"),
        }
    }
}

impl std::str::FromStr for EventType {
    type Err = ();
    fn from_str(input: &str) -> Result<EventType, Self::Err> {
        match input {
            "csv" => Ok(EventType::Csv),
            "log" => Ok(EventType::Log),
            "packet" => Ok(EventType::Packet),
            _ => Err(()),
        }
    }
}

#[macro_export]
macro_rules! bold {
    ($x:expr) => {
        ansi_term::Style::new().bold().paint($x)
    };
}

#[macro_export]
macro_rules! ubold {
    ($x:expr) => {
        Style::new().bold().underline().paint($x)
    };
}

#[macro_export]
macro_rules! blue {
    ($x:expr) => {
        Colour::Blue.paint($x)
    };
}

#[macro_export]
macro_rules! red {
    ($x:expr) => {
        Colour::Red.paint($x)
    };
}

#[macro_export]
macro_rules! boldgreen {
    ($x:expr) => {
        Colour::Green.bold().paint($x)
    };
}

#[macro_export]
macro_rules! boldred {
    ($x:expr) => {
        Colour::Red.bold().paint($x)
    };
}

#[macro_export]
macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

#[derive(
    Debug, Clone, Copy, EnumIter, Eq, FromPrimitive, ToPrimitive, Hash, Ord, PartialOrd, PartialEq,
)]
pub enum Qualifier {
    Benign = 1,
    Unknown = 2,
    Suspicious = 3,
    Mixed = 4,
}

pub const MAX_QUALIFIERS: usize = 4;
pub const ORDERED_QUALIFIERS: [Qualifier; 4] = [
    Qualifier::Benign,
    Qualifier::Unknown,
    Qualifier::Suspicious,
    Qualifier::Mixed,
];

#[derive(Default)]
pub struct QualifierCount {
    count: [usize; ORDERED_QUALIFIERS.len()],
}

impl std::fmt::Display for QualifierCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ORDERED_QUALIFIERS.iter().enumerate().for_each(|(i, q)| {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(f, "{:?} = {}", q, self.count[i]);
        });
        write!(f, "")
    }
}

#[must_use]
pub fn qualifiers_header() -> Vec<String> {
    ORDERED_QUALIFIERS.iter().map(ToString::to_string).collect()
}

impl Default for Qualifier {
    fn default() -> Self {
        Qualifier::Unknown
    }
}

impl std::str::FromStr for Qualifier {
    type Err = ();
    fn from_str(value: &str) -> Result<Qualifier, Self::Err> {
        match value {
            "benign" => Ok(Qualifier::Benign),
            "suspicious" => Ok(Qualifier::Suspicious),
            "unknown" => Ok(Qualifier::Unknown),
            "mixed" => Ok(Qualifier::Mixed),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Qualifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Qualifier::Benign => write!(f, "{}", boldgreen!("benign")),
            Qualifier::Unknown => write!(f, "unknown"),
            Qualifier::Suspicious => write!(f, "{}", boldred!("suspicious")),
            Qualifier::Mixed => write!(f, "mixed"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterOp {
    L,
    LE,
    G,
    GE,
    EQ,
    NE,
}
impl Default for FilterOp {
    fn default() -> Self {
        FilterOp::EQ
    }
}

impl std::fmt::Display for FilterOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterOp::L => write!(f, "<"),
            FilterOp::G => write!(f, ">"),
            FilterOp::LE => write!(f, "<="),
            FilterOp::GE => write!(f, ">="),
            FilterOp::EQ => write!(f, "="),
            FilterOp::NE => write!(f, "<>"),
        }
    }
}

impl std::str::FromStr for FilterOp {
    type Err = ();
    fn from_str(input: &str) -> Result<FilterOp, Self::Err> {
        match input {
            "<" => Ok(FilterOp::L),
            "<=" => Ok(FilterOp::LE),
            ">" => Ok(FilterOp::G),
            ">=" => Ok(FilterOp::GE),
            "=" => Ok(FilterOp::EQ),
            "<>" => Ok(FilterOp::NE),
            _ => Err(()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FilterType {
    NoFilter,
    Auto,
    Count,
    IPaddr,
    Label,
    Qualifier,
    Regex,
    Score,
    LabelScore,
    Sort,
    Status,
    Time,
    Token,
}

impl Default for FilterType {
    fn default() -> Self {
        FilterType::NoFilter
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortType {
    Alphabet,
    Count,
    Score,
}

impl std::fmt::Display for SortType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigType {
    SamplesCount(usize),
    Reverse(bool),
    Samples(bool),
    Signature(bool),
    Tokens(bool),
}

pub struct CliConf {
    pub samples_count: ConfigType,
    pub csv_fields: Vec<usize>,
    pub show_samples: ConfigType,
    pub reverse: ConfigType,
    pub show_signature: ConfigType,
    pub show_tokens: ConfigType,
}
const DEFAULT_SAMPLES_DISPLAY_COUNT: usize = 30;

impl Default for CliConf {
    fn default() -> Self {
        CliConf {
            samples_count: ConfigType::SamplesCount(DEFAULT_SAMPLES_DISPLAY_COUNT),
            csv_fields: Vec::new(),
            show_samples: ConfigType::Samples(true),
            reverse: ConfigType::Reverse(false),
            show_signature: ConfigType::Signature(true),
            show_tokens: ConfigType::Tokens(true),
        }
    }
}

impl CliConf {
    fn samples_count(&self) -> usize {
        if let ConfigType::SamplesCount(count) = self.samples_count {
            count
        } else {
            DEFAULT_SAMPLES_DISPLAY_COUNT
        }
    }

    fn is_show_samples_on(&self) -> bool {
        self.show_samples == ConfigType::Samples(true)
    }

    fn is_show_signature_on(&self) -> bool {
        self.show_signature == ConfigType::Signature(true)
    }

    #[must_use]
    pub fn is_reverse_on(&self) -> bool {
        self.reverse == ConfigType::Reverse(true)
    }

    pub fn set(&mut self, x: ConfigType) {
        match x {
            ConfigType::SamplesCount(_) => self.samples_count = x,
            ConfigType::Reverse(_) => self.reverse = x,
            ConfigType::Samples(_) => self.show_samples = x,
            ConfigType::Signature(_) => self.show_signature = x,
            ConfigType::Tokens(_) => self.show_tokens = x,
        }
    }
}
