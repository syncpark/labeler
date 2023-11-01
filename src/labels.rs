use crate::{config::Load, ClusterId, MessageId, PatternId, RuleId, Score, TidbId};
use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

type RepresentativeLabels = Vec<(ClusterId, Vec<(TidbId, RuleId, usize, Score)>)>;
type EventLabels = Vec<(ClusterId, Vec<(MessageId, Vec<(TidbId, RuleId, Score)>)>)>;
type ClusterByEvents = HashMap<ClusterId, Vec<(MessageId, Vec<(TidbId, RuleId, Score)>)>>;

#[derive(Deserialize)]
#[allow(unused)]
struct DebugLabels {
    representative_labels: usize,
    event_labels: usize,
    representative: RepresentativeLabels,
    events: EventLabels,
}

impl Load for DebugLabels {}

pub struct Labels {
    clusters_labels_map: HashMap<ClusterId, Vec<PatternId>>,
    clusters_events_map: ClusterByEvents,
    labels_clusters_map: HashMap<PatternId, Vec<ClusterId>>,
    representative: RepresentativeLabels,
    events: EventLabels,
}

impl Labels {
    pub fn new(path: &str) -> Result<Self> {
        let debug_labels = DebugLabels::from_path(path)?;
        let mut clusters_labels_map: HashMap<ClusterId, Vec<PatternId>> = HashMap::new();
        let mut clusters_events_map: ClusterByEvents = HashMap::new();
        let mut labels_clusters_map: HashMap<PatternId, Vec<ClusterId>> = HashMap::new();
        for (cluster_id, events) in &debug_labels.events {
            clusters_events_map
                .entry(*cluster_id)
                .or_insert_with(|| events.clone());
            for (_, v) in events {
                for (tidb_id, rule_id, _) in v {
                    clusters_labels_map
                        .entry(*cluster_id)
                        .and_modify(|labels| labels.push((*tidb_id, *rule_id)))
                        .or_insert_with(|| vec![(*tidb_id, *rule_id)]);
                    labels_clusters_map
                        .entry((*tidb_id, *rule_id))
                        .and_modify(|clusters| clusters.push(*cluster_id))
                        .or_insert_with(|| vec![*cluster_id]);
                }
            }
        }
        for patterns in clusters_labels_map.values_mut() {
            patterns.sort_by(|a, b| {
                let aa = (u64::from(a.0) << 32) | u64::from(a.1);
                let bb = (u64::from(b.0) << 32) | u64::from(b.1);
                aa.cmp(&bb)
            });
            patterns.dedup();
        }
        for clusters in labels_clusters_map.values_mut() {
            clusters.sort_unstable();
        }

        Ok(Self {
            clusters_labels_map,
            clusters_events_map,
            labels_clusters_map,
            representative: debug_labels.representative,
            events: debug_labels.events,
        })
    }

    pub fn get_representative_labels(
        &self,
        cluster_id: ClusterId,
    ) -> Option<&Vec<(TidbId, RuleId, usize, Score)>> {
        if let Some((_, labels)) = self
            .representative
            .iter()
            .find(|(cid, _)| *cid == cluster_id)
        {
            Some(labels)
        } else {
            None
        }
    }

    pub fn get_event_labels(&self, cluster_id: ClusterId) -> Option<Vec<(PatternId, usize)>> {
        let mut patterns = HashMap::new();
        if let Some(v) = self.clusters_events_map.get(&cluster_id) {
            for (_, vv) in v {
                for (tidb_id, rule_id, _) in vv {
                    patterns
                        .entry((*tidb_id, *rule_id))
                        .and_modify(|c| *c += 1)
                        .or_insert(1_usize);
                }
            }
        }
        let mut patterns: Vec<_> = patterns.into_iter().collect();
        patterns.sort_by(|a, b| {
            let aa = (u64::from(a.0 .0) << 32) | u64::from(a.0 .1);
            let bb = (u64::from(b.0 .0) << 32) | u64::from(b.0 .1);
            aa.cmp(&bb)
        });
        if patterns.is_empty() {
            None
        } else {
            Some(patterns)
        }
    }

    /// Calculate
    /// * the number of labeled clustgers
    /// * the number of distinct labeled events
    /// * the number of representative labels
    pub fn statistics(&self) -> (usize, usize, usize) {
        let labeled_clusters = self.clusters_labels_map.len();
        let labeled_events: HashSet<String> = self
            .events
            .iter()
            .flat_map(|(_, v)| {
                v.iter()
                    .map(|(vv, _)| vv.to_string())
                    .collect::<Vec<String>>()
            })
            .collect();
        let representatives = self.representative.len();

        (labeled_clusters, labeled_events.len(), representatives)
    }

    pub fn find_clusters(&self, tidb_id: TidbId, rule_id: RuleId) -> Vec<ClusterId> {
        let mut found = Vec::new();
        for (pattern_id, clusters) in &self.labels_clusters_map {
            if (pattern_id.0 == tidb_id || tidb_id == 0)
                && (pattern_id.1 == rule_id || rule_id == 0)
            {
                found.extend(clusters);
            }
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    pub fn is_labeled(&self, cluster_id: ClusterId) -> bool {
        self.clusters_labels_map.contains_key(&cluster_id)
    }
}
