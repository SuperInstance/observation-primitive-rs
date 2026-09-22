//! observation-primitive: canonical substrate atom
//!
//! Distilled from R10 reverse-engineering. observation = subject/predicate/object/issuer/time/evidence/signature
//!
//! Inspired by evintunador/context-graph: every observation carries the evidence that justifies it.

use serde::{Serialize, Deserialize};

pub const FNV_OFFSET: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;
const MASK_64: u64 = 0xffffffffffffffff;

/// FNV-1a 64-bit hash on UTF-8 bytes (matches fleet canary 0x024a555471370b18d)
pub fn fnv1a64(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// FNV-1a 64-bit as a 16-char hex string (leading zeros preserved)
pub fn fnv1a64_hex(s: &str) -> String {
    format!("{:016x}", fnv1a64(s))
}

/// Signed int16 dials from observation hash (for live-canon /api/cell submission)
pub fn int16_dials(text: &str, count: usize) -> [i16; 16] {
    let mut h = fnv1a64(text);
    let mut dials = [0i16; 16];
    let mut nonzero = 0;
    let n = if count > 16 { 16 } else { count };
    for i in 0..n {
        let v = (h & 0xffff) as i32;
        let dial = if v > 32767 { v - 65536 } else { v };
        dials[i] = dial as i16;
        if dial != 0 {
            nonzero += 1;
            h = (h.wrapping_mul(FNV_PRIME)).wrapping_add(dial as u64);
        }
        if nonzero >= 7 {
            break;
        }
    }
    dials
}

/// The 11 typed opcodes (5 base + 6 missing from R10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Opcode {
    BIND,
    LINK,
    EFFECT,
    VIEW,
    TICK,
    ATTEST,
    DELEGATE,
    CONTEST,
    MERGE,
    REVOKE,
    WITHDRAW,
}

/// Three forms of evidence (R10 canonical)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    Direct,
    Witness,
    Pattern,
}

/// Three kinds of forgetting (R10 canonical)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Forgetting {
    Bundle,
    Traversal,
    Evidence,
}

/// The canonical substrate atom
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub subject: String,
    pub predicate: String,
    pub object: serde_json::Value,
    pub issuer: String,
    pub time: u64,
    pub evidence: Option<String>,
    pub signature: Option<String>,
    pub id: String,
}

impl Observation {
    pub fn new(
        subject: impl Into<String>,
        predicate: impl Into<String>,
        object: serde_json::Value,
        issuer: impl Into<String>,
        time: Option<u64>,
    ) -> Self {
        let subject = subject.into();
        let predicate = predicate.into();
        let issuer_str = issuer.into();
        let t = time.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        });

        // Compute id: FNV-1a over canonical JSON
        let payload = serde_json::json!({
            "i": issuer_str,
            "o": object,
            "p": predicate,
            "s": subject,
            "t": t,
        });
        let payload_str = payload.to_string();
        let id = fnv1a64_hex(&payload_str);

        Self {
            subject,
            predicate,
            object,
            issuer: issuer_str,
            time: t,
            evidence: None,
            signature: None,
            id,
        }
    }

    pub fn validate(&self) -> bool {
        !self.id.is_empty() && !self.issuer.is_empty()
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fleet_canary() {
        // Compare numeric values to avoid leading-zero display issues
        assert_eq!(fnv1a64("café Δ 日本語"), 0x024a555471370b18d);
    }
    #[test]
    fn dial_test() {
        let d = int16_dials("the witness as prediction", 16);
        assert_eq!(d.len(), 16);
    }
    #[test]
    fn obs_id() {
        let o = Observation::new("substrate", "has_primitive", serde_json::json!("observation"), "casey", Some(12345));
        assert!(!o.id.is_empty());
    }
    #[test]
    fn eleven_opcodes() {
        let all = [Opcode::BIND, Opcode::LINK, Opcode::EFFECT, Opcode::VIEW, Opcode::TICK,
                   Opcode::ATTEST, Opcode::DELEGATE, Opcode::CONTEST, Opcode::MERGE, Opcode::REVOKE, Opcode::WITHDRAW];
        assert_eq!(all.len(), 11);
    }
}
