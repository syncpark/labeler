use crate::config::Load;
use crate::events::Events;
use crate::labels::Labels;
use crate::{CliConf, ClusterId, FilterOp, FilterType, MessageId, Qualifier, Score};
use anyhow::Result;
use log::info;
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

const SIGNATURE_DISPLAY_LENGTH: usize = 200;
const CLUSTER_ID_FOR_OUTLIERS: ClusterId = 1_000_000;
#[derive(Deserialize)]
struct SavedClusters {
    detector_id: i32,
    events_count: usize,
    clusters_count: usize,
    outlier_count: usize,
    clusters: Vec<ClusterMember>,
    outliers: Vec<String>,
}

#[derive(Deserialize)]
struct ClusterMember {
    cluster_id: usize,
    cluster_size: usize,
    signature: Option<String>,
    score: Option<f32>,
    events: Vec<String>,
}

impl Load for SavedClusters {}

impl SavedClusters {
    fn cluster_ids(&self) -> Vec<ClusterId> {
        let mut clusters: Vec<_> = self.clusters.iter().map(|c| c.cluster_id).collect();
        clusters.sort_unstable();
        clusters
    }

    pub fn attributes(&self) -> (i32, usize, usize, usize) {
        (
            self.detector_id,
            self.events_count,
            self.clusters_count,
            self.outlier_count,
        )
    }
    fn outliers(&self) -> &Vec<String> {
        &self.outliers
    }
}

#[derive(Debug, Default, Clone)]
pub struct Members {
    id: ClusterId,
    size: usize,
    score: Score,
    qualifier: Qualifier,
    new_qualifier: Qualifier,
    signature: Option<String>,
    event_ids: Vec<MessageId>,
    filtered_events: Vec<Vec<MessageId>>, // tokens: HashMap<String, Vec<MessageId>>, // TODO: calculate token occurrences to correct label-score
    filter: Vec<String>,
}

impl fmt::Display for Members {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " cluster {}", self.id)?;
        if self.qualifier == self.new_qualifier {
            write!(f, ", {}", self.new_qualifier)?;
        } else {
            write!(f, ", {}<-{}", self.new_qualifier, self.qualifier)?;
        }
        write!(f, ", {} events", self.size)?;
        write!(f, ", score = {}", self.score)
    }
}

impl Members {
    #[must_use]
    pub fn signature(&self) -> Option<String> {
        if let Some(s) = &self.signature {
            if s.len() > SIGNATURE_DISPLAY_LENGTH {
                Some(format!(
                    "{}... ({})",
                    s.get(..SIGNATURE_DISPLAY_LENGTH).unwrap_or(""),
                    s.len()
                ))
            } else {
                Some(s.clone())
            }
        } else {
            None
        }
    }

    pub fn set_qualifier(&mut self, qualifier: Qualifier) -> bool {
        if self.new_qualifier != qualifier {
            self.new_qualifier = qualifier;
            return true;
        }
        false
    }
}

#[derive(Debug, Default, Clone)]
pub struct Clusters {
    clusters: Vec<ClusterId>,
    _outliers: Vec<String>,
    clusters_map: HashMap<ClusterId, Members>,
    tokens_clusters_map: HashMap<String, Vec<ClusterId>>,
}

impl Clusters {
    /// # Errors
    ///
    /// Will return `Err` if the query to get cluster records for the specified datasource failed.
    pub fn new(path: &str, labels: &Labels, delimiter: char) -> Result<Self> {
        let save_clusters = SavedClusters::from_path(path)?;
        {
            let (detector_id, events_count, clusters_count, outliers_count) =
                save_clusters.attributes();
            info!(
                "{} loaded. detector {}, {} events, {} clusters, {} outliers",
                path, detector_id, events_count, clusters_count, outliers_count
            );
        }
        let mut clusters = save_clusters.cluster_ids();
        let mut clusters_map: HashMap<ClusterId, Members> = save_clusters
            .clusters
            .iter()
            .map(|m| {
                let qualifier = if labels.is_labeled(m.cluster_id) {
                    Qualifier::Suspicious
                } else {
                    Qualifier::default()
                };
                (
                    m.cluster_id,
                    Members {
                        id: m.cluster_id,
                        size: m.cluster_size,
                        score: m.score.unwrap_or_default(),
                        qualifier,
                        new_qualifier: qualifier,
                        signature: m.signature.as_ref().cloned(),
                        event_ids: m.events.clone(),
                        filtered_events: Vec::new(),
                        filter: Vec::new(),
                    },
                )
            })
            .collect();

        if !save_clusters.outliers().is_empty() {
            let message_id_index = 1;
            let event_ids: Vec<_> = save_clusters
                .outliers()
                .iter()
                .filter_map(|raw| {
                    let s: Vec<_> = raw.split(delimiter).collect();
                    s.get(message_id_index).map(|msg_id| (*msg_id).to_string())
                })
                .collect();
            clusters_map.insert(
                CLUSTER_ID_FOR_OUTLIERS,
                Members {
                    id: CLUSTER_ID_FOR_OUTLIERS,
                    size: save_clusters.outliers().len(),
                    score: 0.0,
                    qualifier: Qualifier::default(),
                    new_qualifier: Qualifier::default(),
                    signature: None,
                    event_ids,
                    filtered_events: Vec::new(),
                    filter: Vec::new(),
                },
            );
            clusters.push(CLUSTER_ID_FOR_OUTLIERS);
        }

        Ok(Self {
            clusters,
            _outliers: save_clusters.outliers,
            clusters_map,
            tokens_clusters_map: HashMap::new(),
        })
    }

    pub fn event_ids(&self) -> Vec<String> {
        self.clusters_map
            .values()
            .flat_map(|c| c.event_ids.clone())
            .collect()
    }

    pub fn init_event_tokens(&mut self, events: &Events) {
        let mut tokens_clusters_map: HashMap<String, Vec<ClusterId>> = HashMap::new();
        for cd in self.clusters_map.values() {
            for message_id in &cd.event_ids {
                if let Some(tokens) = events.tokens(message_id) {
                    for token in tokens {
                        tokens_clusters_map
                            .entry(token.to_string())
                            .and_modify(|cs| cs.push(cd.id))
                            .or_insert_with(|| vec![cd.id]);
                    }
                }
            }
        }

        for cs in tokens_clusters_map.values_mut() {
            cs.sort_unstable();
            cs.dedup();
        }

        self.tokens_clusters_map = tokens_clusters_map;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.clusters.len()
    }

    pub fn size(&self, cluster_id: ClusterId) -> usize {
        self.clusters_map
            .get(&cluster_id)
            .map(|c| c.size)
            .unwrap_or_default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty()
    }

    pub fn clear_filter(&mut self, cluster_id: ClusterId) {
        if let Some(c) = self.clusters_map.get_mut(&cluster_id) {
            c.filtered_events.clear();
            c.filter.clear();
        }
    }

    pub fn print(&self, cid: ClusterId, events: &Events, cfg: &CliConf) {
        if let Some(c) = self.clusters_map.get(&cid) {
            println!("{}", c);
            if cfg.is_show_signature_on() {
                if let Some(sig) = c.signature() {
                    println!("signature = {}", sig);
                }
            }
            if !c.filter.is_empty() {
                println!("Event Filter: {:#?}", c.filter);
            }
            if cfg.is_show_samples_on() {
                let display_count = cfg.samples_count();
                let event_ids = if let Some(last) = c.filtered_events.last() {
                    last
                } else {
                    &c.event_ids
                };
                println!();
                for (idx, message_id) in event_ids.iter().enumerate() {
                    if idx > display_count {
                        println!("... {} more events", event_ids.len() - display_count);
                        break;
                    }
                    if let Some(msg) = events.get_message(message_id) {
                        println!("{}", msg);
                    } else {
                        println!("{}", message_id);
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn cluster_list(&self) -> &Vec<ClusterId> {
        &self.clusters
    }

    #[must_use]
    pub fn filter_clusters(
        &self,
        clusters: &[ClusterId],
        ft: FilterType,
        op: FilterOp,
        value: &str,
    ) -> Vec<ClusterId> {
        clusters
            .iter()
            .filter_map(|cid| {
                if let Some(c) = self.clusters_map.get(cid) {
                    let matched = match ft {
                        FilterType::Count => {
                            let count = value.parse::<usize>().unwrap_or_default();
                            match op {
                                FilterOp::L => c.size < count,
                                FilterOp::G => c.size > count,
                                FilterOp::LE => c.size <= count,
                                FilterOp::GE => c.size >= count,
                                FilterOp::EQ => c.size == count,
                                FilterOp::NE => c.size != count,
                            }
                        }
                        FilterType::Score => {
                            let score = value.parse::<f32>().unwrap_or_default();
                            match op {
                                FilterOp::L => c.score < score,
                                FilterOp::G => c.score > score,
                                FilterOp::LE => c.score <= score,
                                FilterOp::GE => c.score >= score,
                                FilterOp::EQ => (c.score - score).abs() < f32::EPSILON,
                                FilterOp::NE => (c.score - score).abs() > f32::EPSILON,
                            }
                        }
                        FilterType::Qualifier => {
                            let qualifier = Qualifier::from_str(value).unwrap_or_default();
                            c.new_qualifier == qualifier
                        }
                        _ => false,
                    };

                    if matched {
                        Some(*cid)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn regex_match(
        &self,
        clusters: &[ClusterId],
        pattern: &str,
        events: &Events,
    ) -> Result<Vec<ClusterId>> {
        let re = Regex::new(pattern)?;
        Ok(clusters
            .iter()
            .filter_map(|cid| {
                if let Some(c) = self.clusters_map.get(cid) {
                    let matched = events.regex_match(&re, &c.event_ids);
                    if matched.is_empty() {
                        None
                    } else {
                        Some(*cid)
                    }
                } else {
                    None
                }
            })
            .collect())
    }

    pub fn regex_match_in_this_cluster(
        &self,
        cluster_id: ClusterId,
        pattern: &str,
        events: &Events,
    ) -> Result<Option<Vec<MessageId>>> {
        let mut negate: bool = false;
        let pattern = if pattern.starts_with('!') {
            if pattern.len() == 1 {
                return Ok(None);
            }
            negate = true;
            pattern.get(1..).unwrap_or(pattern)
        } else {
            pattern
        };

        let re = Regex::new(pattern)?;
        Ok(self.clusters_map.get(&cluster_id).map(|c| {
            let cluster_event_ids = if let Some(last) = c.filtered_events.last() {
                last
            } else {
                &c.event_ids
            };
            let matched = events.regex_match(&re, cluster_event_ids);
            if negate {
                let set_matched: HashSet<_> = matched.into_iter().collect();
                let set_cluster: HashSet<_> = cluster_event_ids.iter().cloned().collect();
                (&set_cluster - &set_matched).into_iter().collect()
            } else {
                matched
            }
        }))
    }

    pub fn set_filtered(&mut self, cluster_id: ClusterId, matched: Vec<MessageId>, pattern: &str) {
        if let Some(c) = self.clusters_map.get_mut(&cluster_id) {
            c.filter.push(pattern.to_string());
            c.filtered_events.push(matched);
        }
    }

    pub fn set_qualifier(&mut self, cid: ClusterId, qualifier: Qualifier) -> bool {
        if let Some(c) = self.clusters_map.get_mut(&cid) {
            return c.set_qualifier(qualifier);
        }
        false
    }
}
