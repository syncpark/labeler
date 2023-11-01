use crate::config::Config;
use crate::{parser, MessageId};
use anyhow::{anyhow, Result};
use log::info;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Default, Clone)]
pub struct Message {
    _id: MessageId,
    content: String,
    tokens: Vec<String>,
}

#[derive(Default, Clone)]
pub struct Events {
    events: HashMap<MessageId, Message>,
    // tokens_events_map: HashMap<Vec<String>, Vec<MessageId>>,
    // outliers: Vec<MessageId>,
}

impl Events {
    /// # Panics
    /// * if `key_column` field does not find in column format aliases
    ///
    /// # Errors
    ///
    /// Will return Err if it fails to open events file.
    pub fn new(cfg: &Config, event_ids: Vec<MessageId>) -> Result<Self> {
        let key_idx = cfg
            .key_field()
            .ok_or_else(|| anyhow!("key_field does not set"))?;
        let features = cfg.features();
        let column_len = cfg.column_len();
        let delimiter = cfg.delimiter();
        let event_ids: HashSet<MessageId> = event_ids.into_iter().collect();

        let file = File::open(cfg.events())?;
        let lines = BufReader::new(file).lines();
        let mut events = HashMap::new();
        let mut skipped = 0;
        let mut notfound = 0;
        for line in lines.flatten() {
            let log: Vec<_> = line.split(delimiter).collect();
            if log.len() != column_len {
                skipped += 1;
                continue;
            }
            let key = if let Some(key) = log.get(key_idx) {
                if event_ids.contains(*key) {
                    key
                } else {
                    notfound += 1;
                    continue;
                }
            } else {
                notfound += 1;
                continue;
            };
            let mut tokens = Vec::new();
            for feature_idx in &features {
                if let Some(value) = log.get(*feature_idx) {
                    tokens.extend(parser::extract_tokens(value));
                }
            }
            events.insert(
                (*key).to_string(),
                Message {
                    _id: (*key).to_string(),
                    content: line,
                    tokens,
                },
            );
        }
        info!("{} skipped events, {} not found", skipped, notfound);

        // let mut tokens_events_map: HashMap<Vec<String>, Vec<MessageId>> = HashMap::new();
        // for (id, msg) in &events {
        //     tokens_events_map
        //         .entry(msg.tokens.clone())
        //         .and_modify(|message_ids| message_ids.push(id.to_string()))
        //         .or_insert(vec![id.to_string()]);
        // }

        Ok(Self {
            events,
            // tokens_events_map,
            // outliers: Vec::new(),
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn tokens(&self, message_id: &MessageId) -> Option<&Vec<String>> {
        self.events.get(message_id).map(|m| &m.tokens)
    }

    #[must_use]
    pub fn regex_match(&self, re: &Regex, event_ids: &[MessageId]) -> Vec<String> {
        event_ids
            .iter()
            .filter_map(|msg_id| {
                self.events.get(msg_id).map(|event| {
                    if re.is_match(&event.content) {
                        Some(msg_id.to_string())
                    } else {
                        None
                    }
                })
            })
            .flatten()
            .collect()
        // for msg_id in event_ids {
        //     if let Some(evt) = self.events.get(msg_id) {
        //         if re.is_match(&evt.content) {
        //             return true;
        //         }
        //     }
        // }
        // false
    }

    #[must_use]
    pub fn get_message(&self, message_id: &MessageId) -> Option<&str> {
        self.events
            .get(message_id)
            .map(|message| message.content.as_str())
    }
}
