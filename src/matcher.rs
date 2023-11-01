use crate::cluster::Clusters;
use crate::config::Config;
use crate::events::Events;
use crate::labels::Labels;
use crate::tidb::ComplexRules;
use crate::{bold, CliConf, ClusterId, EventType, FilterOp, FilterType, Qualifier, RuleId, TidbId};
use anyhow::{anyhow, Result};
use log::info;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

/// This structure stores the result of `cli` command `/filter ipaddr/regex/label/...`
#[derive(Default)]
pub struct FilteredClusters {
    filtertype: FilterType,
    op: FilterOp,
    pattern: String,
    clusters: Vec<ClusterId>,
}

impl fmt::Display for FilteredClusters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.filtertype == FilterType::NoFilter {
            write!(f, " (All): ")
        } else {
            write!(f, " ({:?} {} {}): ", self.filtertype, self.op, self.pattern)
        }
    }
}

pub struct TitleMatch {
    clusters: Clusters,
    events: Events,
    tidbs: Vec<ComplexRules>,
    labels: Labels,
    rounds: Vec<FilteredClusters>,
}

impl TitleMatch {
    /// # Errors
    ///
    /// Will return `Err` if it fails to connect postgres db or datasource not found
    pub fn new(cfg: &Config) -> Result<Self> {
        if EventType::Packet == cfg.event_type() {
            return Err(anyhow!("unsupported log type {:?}", cfg.event_type()));
        }

        info!("loading labels");
        let labels = Labels::new(cfg.labels())?;

        info!("loading clusters");
        let mut clusters = Clusters::new(cfg.clusters(), &labels, cfg.delimiter())?;
        if clusters.is_empty() {
            return Err(anyhow!("clusters not found."));
        }
        info!("{} clusters are loaded.", clusters.len());

        info!("loading events");
        let events = Events::new(cfg, clusters.event_ids())?;
        if events.is_empty() {
            return Err(anyhow!("events not found."));
        }
        info!("{} events are loaded.", events.len());

        clusters.init_event_tokens(&events);

        info!("loading tidb");
        let tidbs = ComplexRules::new(cfg.tidb())?;

        // init base(bottom filter) layer
        let rounds: Vec<FilteredClusters> = vec![FilteredClusters {
            filtertype: FilterType::default(),
            op: FilterOp::default(),
            pattern: String::from("Clusters"),
            clusters: clusters.cluster_list().clone(),
        }];

        Ok(TitleMatch {
            clusters,
            events,
            tidbs,
            labels,
            rounds,
        })
    }

    pub fn show_statistics(&self) {
        let (labeled_clusters, labeled_events, representative_labels) = self.labels.statistics();
        println!(
            "{:>6} clusters\n{:>6} labeled clusters\n{:>6} labeled events\n{:>6} representatives",
            self.clusters.len(),
            labeled_clusters,
            labeled_events,
            representative_labels
        );
    }

    #[must_use]
    pub fn count_clusters(&self) -> usize {
        self.clusters.len()
    }

    pub fn print_cluster(&self, idx: usize, cfg: &CliConf) {
        if let Some(last) = self.rounds.last() {
            if idx >= last.clusters.len() {
                return;
            }
            let cid = last.clusters[idx];
            print!("[{}]", idx);
            self.clusters.print(cid, &self.events, cfg);

            let cluster_size = u32::try_from(self.clusters.size(cid)).unwrap_or_default();
            if let Some(matched) = self.labels.get_representative_labels(cid) {
                println!("\n{}", bold!("Cluster label(s):"));
                for (tidb_id, rule_id, count, score) in matched {
                    if let Some(name) = Self::get_label_name(self, *tidb_id, *rule_id) {
                        let score = f64::try_from(*score).unwrap_or_default();
                        let dividend = f64::try_from(cluster_size).unwrap_or_default();
                        if dividend > 0.0 {
                            println!(
                                "{:.03} {}/{} {}:{} {}",
                                score / dividend,
                                count,
                                cluster_size,
                                tidb_id,
                                rule_id,
                                name
                            );
                        }
                    }
                }
            }

            if let Some(matched) = self.labels.get_event_labels(cid) {
                println!("\n{}", bold!("Event label(s):"));
                let mut unknowns = Vec::new();
                for ((tidb_id, rule_id), count) in matched {
                    if let Some(name) = Self::get_label_name(self, tidb_id, rule_id) {
                        println!("{:>4} {}:{} {}", count, tidb_id, rule_id, name);
                    } else {
                        unknowns.push(tidb_id);
                    }
                }

                unknowns.sort_unstable();
                unknowns.dedup();
                for tidb_id in unknowns {
                    if let Some(name) = Self::get_tidb_name(self, tidb_id) {
                        println!("{} {}", tidb_id, name);
                    } else {
                        println!("{:>8}:", tidb_id);
                    }
                }
            }
        }
    }

    fn get_tidb_name(&self, tidb_id: TidbId) -> Option<&str> {
        for tidb in &self.tidbs {
            if tidb.id() == tidb_id {
                return Some(tidb.name());
            }
        }
        None
    }

    fn get_label_name(&self, tidb_id: TidbId, rule_id: RuleId) -> Option<&str> {
        for tidb in &self.tidbs {
            let r = tidb.get_label_name(tidb_id, rule_id);
            if r.is_some() {
                return r;
            }
        }
        None
    }

    #[must_use]
    pub fn find_cluster(&self, cid: ClusterId) -> Option<usize> {
        if let Some(last) = self.rounds.last() {
            last.clusters.iter().position(|i| *i == cid)
        } else {
            None
        }
    }

    pub fn filter_by(&mut self, ft: FilterType, op: FilterOp, value: &str) -> Option<usize> {
        let clusters = self
            .clusters
            .filter_clusters(&self.rounds.last()?.clusters, ft, op, value);
        info!(
            "filtering by \"{:?} {} {}\". {} clusters",
            ft,
            op,
            value,
            clusters.len()
        );
        if clusters.is_empty() {
            None
        } else {
            let cnt = clusters.len();
            let pattern = if let FilterType::Qualifier = ft {
                value.to_string()
            } else {
                format!("{} {}", op, value)
            };
            self.rounds.push(FilteredClusters {
                filtertype: ft,
                op,
                pattern,
                clusters,
            });
            Some(cnt)
        }
    }

    /// Filter clusters with label.
    /// if `pattern_id` is none, then all labels.
    ///
    /// Return the number of filtered clusters
    pub fn filter_by_label(
        &mut self,
        ft: FilterType,
        op: FilterOp,
        pattern_id: Option<&str>,
    ) -> Option<usize> {
        let (tidb_id, rule_id) = parse_pattern_id(pattern_id);
        let last = &self.rounds.last()?.clusters;
        let mut found = self.labels.find_clusters(tidb_id, rule_id);
        found.retain(|cluster_id| last.contains(cluster_id));
        if found.is_empty() {
            None
        } else {
            let cnt = found.len();
            let pattern = if let Some(v) = pattern_id {
                v.to_string()
            } else {
                String::from("All")
            };

            self.rounds.push(FilteredClusters {
                filtertype: ft,
                op,
                pattern,
                clusters: found,
            });
            Some(cnt)
        }
    }

    pub fn filter_by_regex(&mut self, pattern: &str) -> Option<usize> {
        let last = self.rounds.last()?;

        /* ! => negation (trick!!!) */
        let mut negate: bool = false;
        let pattern = if pattern.starts_with('!') {
            if pattern.len() == 1 {
                return None;
            }
            negate = true;
            pattern.get(1..).unwrap_or(pattern)
        } else {
            pattern
        };

        match self
            .clusters
            .regex_match(&last.clusters, pattern, &self.events)
        {
            Ok(mut clusters) => {
                if negate {
                    clusters = last
                        .clusters
                        .iter()
                        .filter(|cid| !clusters.contains(cid))
                        .copied()
                        .collect();
                }

                if clusters.is_empty() {
                    None
                } else {
                    let cnt = clusters.len();
                    self.rounds.push(FilteredClusters {
                        filtertype: FilterType::Regex,
                        op: FilterOp::EQ,
                        pattern: pattern.to_string(),
                        clusters,
                    });
                    Some(cnt)
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                None
            }
        }
    }

    /// # Errors
    /// * Will return error if unknown cluster is specified
    /// * Will return error if regular expression has invalid syntax
    pub fn filter_event(
        &mut self,
        ft: FilterType,
        pattern: Option<&str>,
        ticks: &Option<usize>,
    ) -> Result<usize> {
        let mut filtered_events_count = 0;
        if let Some(index) = ticks {
            let cluster_id = self
                .rounds
                .last()
                .and_then(|last| last.clusters.get(*index))
                .ok_or_else(|| anyhow!("Cluster {} not found", index))?;
            match ft {
                FilterType::NoFilter => self.clusters.clear_filter(*cluster_id),
                FilterType::Regex => {
                    if let Some(pattern) = pattern {
                        match self.clusters.regex_match_in_this_cluster(
                            *cluster_id,
                            pattern,
                            &self.events,
                        ) {
                            Err(e) => eprintln!("Error: {}", e),
                            Ok(matched) => {
                                if let Some(matched) = matched {
                                    filtered_events_count = matched.len();
                                    self.clusters.set_filtered(*cluster_id, matched, pattern);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(filtered_events_count)
    }
    /// # Errors
    ///
    /// Will return `Err` if a try to remove on an empty filter
    pub fn remove_filter(&mut self) -> Result<()> {
        if self.rounds.is_empty() {
            Err(anyhow!("Failed to remove the filtered clusters."))
        } else {
            let _r = self.rounds.pop();
            Ok(())
        }
    }

    pub fn set_qualifier(&mut self, idx: usize, qualifier: &str, all: bool) -> Option<usize> {
        let last = self.rounds.last()?;

        let mut cnt: usize = 0;
        let nq = Qualifier::from_str(qualifier).ok()?;

        if all {
            for cid in &last.clusters {
                if self.clusters.set_qualifier(*cid, nq) {
                    cnt += 1;
                }
            }
            println!("{} clusters updated to {}", cnt, qualifier);
        } else {
            if idx >= last.clusters.len() {
                println!("Cluster not found!\n");
                return None;
            }

            let cid = last.clusters[idx];
            if self.clusters.set_qualifier(cid, nq) {
                cnt += 1;
                println!("cluster #{} updated to {}", cid, nq);
            }
        }
        Some(cnt)
    }
}

fn parse_pattern_id(pattern_id: Option<&str>) -> (u32, u32) {
    let mut tidb_id: TidbId = 0;
    let mut rule_id: RuleId = 0;
    if let Some(id) = pattern_id {
        let s: Vec<_> = id.split(':').collect();
        if let Some(v) = s.first() {
            if let Ok(vv) = v.parse::<TidbId>() {
                tidb_id = vv;
            }
        }
        if let Some(v) = s.get(1) {
            if let Ok(vv) = v.parse::<RuleId>() {
                rule_id = vv;
            }
        }
    }
    (tidb_id, rule_id)
}
