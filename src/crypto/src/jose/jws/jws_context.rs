use std::collections::BTreeSet;
use std::fmt::Debug;

use anyhow::bail;

use crate::jose::error::JoseError;

use super::alg::{JwsSigner, JwsVerifier};
use super::header::{JwsHeader, JwsHeaderSet};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwsContext {
    acceptable_criticals: BTreeSet<String>,
}

impl JwsContext {
    pub fn new() -> Self {
        Self {
            acceptable_criticals: BTreeSet::new(),
        }
    }

    pub fn is_acceptable_critical(&self, name: &str) -> bool {
        self.acceptable_criticals.contains(name)
    }

    pub fn add_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.insert(name.to_string());
    }

    pub fn remove_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.remove(name);
    }
}
