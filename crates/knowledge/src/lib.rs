//! Deterministic governed knowledge-context selection.
//!
//! This crate is deliberately a pure domain layer. It accepts an already
//! authorized, immutable set of [`EntryRevision`] values and produces one
//! self-contained [`SelectionSnapshot`]. It does not read live knowledge,
//! resolve permissions, access storage, or call a model. Callers must persist
//! the exact snapshot they admitted; rebuilding from a newer corpus would be a
//! different selection.
//!
//! Version 1 has intentionally small and explicit resource envelopes. Ranking
//! uses only integer term frequencies. Entries are either rendered in full or
//! omitted in full, and canonical context never exceeds 16 KiB.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

type TermFrequencies = BTreeMap<String, u32>;

pub const SELECTION_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const SELECTION_SNAPSHOT_ENVELOPE_SCHEMA_VERSION: u16 = 1;
pub const CORPUS_REVISION_ENVELOPE_SCHEMA_VERSION: u16 = 1;
pub const TOKENIZER_REVISION: &str = "zeus.lexical-tokenizer.v1";
pub const SCORING_REVISION: &str = "zeus.integer-lexical.v1";
pub const CONTEXT_RENDERER_REVISION: &str = "zeus.canonical-knowledge-context.v1";

pub const MAX_ENTRY_REVISIONS: usize = 256;
pub const MAX_ENTRY_ID_BYTES: usize = 128;
pub const MAX_ENTRY_REVISION_BYTES: usize = 128;
pub const MAX_ENTRY_TITLE_BYTES: usize = 256;
pub const MAX_ENTRY_CONTENT_BYTES: usize = 8 * 1024;
pub const MAX_AGGREGATE_ENTRY_BYTES: usize = 512 * 1024;
pub const MAX_QUERY_BYTES: usize = 4 * 1024;
pub const MAX_QUERY_UNIQUE_TERMS: usize = 32;
pub const MAX_ENTRY_UNIQUE_TERMS: usize = 256;
pub const MAX_SELECTION_HITS: usize = 6;
pub const MAX_CANONICAL_CONTEXT_BYTES: usize = 16 * 1024;
pub const MAX_SELECTION_SNAPSHOT_BYTES: usize = 256 * 1024;
pub const MAX_CORPUS_REVISION_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

pub const TITLE_TOKEN_WEIGHT: u64 = 8;
pub const CONTENT_TOKEN_WEIGHT: u64 = 2;

const QUERY_DIGEST_DOMAIN: &[u8] = b"zeus.knowledge-query.sha256.v1";
const CORPUS_DIGEST_DOMAIN: &[u8] = b"zeus.knowledge-corpus.sha256.v1";
const ENTRY_CONTENT_DIGEST_DOMAIN: &[u8] = b"zeus.knowledge-entry-content.sha256.v1";
const CONTEXT_DIGEST_DOMAIN: &[u8] = b"zeus.knowledge-context.sha256.v1";
const SELECTION_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"zeus.knowledge-selection.sha256.v1";

/// A canonical lowercase SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn from_hex(value: &str) -> Result<Self, KnowledgeError> {
        if value.len() != 64 {
            return Err(KnowledgeError::InvalidDigest);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or(KnowledgeError::InvalidDigest)?;
            let low = decode_hex(pair[1]).ok_or(KnowledgeError::InvalidDigest)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(encode_hex(byte >> 4));
            output.push(encode_hex(byte & 0x0f));
        }
        output
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// One immutable revision supplied by an authorized knowledge-corpus reader.
///
/// Fields are private so a validated revision cannot be changed in place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EntryRevision {
    entry_id: String,
    revision: String,
    title: String,
    content: String,
}

impl EntryRevision {
    pub fn new(
        entry_id: impl Into<String>,
        revision: impl Into<String>,
        title: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, KnowledgeError> {
        let value = Self {
            entry_id: entry_id.into(),
            revision: revision.into(),
            title: title.into(),
            content: content.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), KnowledgeError> {
        validate_identifier("entry_id", &self.entry_id, MAX_ENTRY_ID_BYTES)?;
        validate_identifier("entry_revision", &self.revision, MAX_ENTRY_REVISION_BYTES)?;
        validate_title(&self.title)?;
        validate_content(&self.content)
    }

    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn content_digest(&self) -> Sha256Digest {
        content_digest(&self.content)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryRevisionWire {
    entry_id: String,
    revision: String,
    title: String,
    content: String,
}

impl<'de> Deserialize<'de> for EntryRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EntryRevisionWire::deserialize(deserializer)?;
        Self::new(wire.entry_id, wire.revision, wire.title, wire.content)
            .map_err(serde::de::Error::custom)
    }
}

/// Canonical, digest-bearing representation of one exact immutable corpus.
///
/// Construction sorts revisions by identity, so callers cannot create two
/// durable encodings for the same set. The digest remains account-neutral;
/// storage must bind it to an account before admitting an Agent turn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CorpusRevisionEnvelope {
    schema_version: u16,
    digest: Sha256Digest,
    entries: Vec<EntryRevision>,
}

impl CorpusRevisionEnvelope {
    pub fn new(mut entries: Vec<EntryRevision>) -> Result<Self, KnowledgeError> {
        validate_entry_revisions(&entries)?;
        entries.sort_by(compare_entry_identity);
        let digest = corpus_digest_unchecked(&entries);
        let envelope = Self {
            schema_version: CORPUS_REVISION_ENVELOPE_SCHEMA_VERSION,
            digest,
            entries,
        };
        let _ = envelope.canonical_json()?;
        Ok(envelope)
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub fn entries(&self) -> &[EntryRevision] {
        &self.entries
    }

    pub fn validate(&self) -> Result<(), KnowledgeError> {
        if self.schema_version != CORPUS_REVISION_ENVELOPE_SCHEMA_VERSION {
            return Err(invalid_snapshot(
                "unsupported corpus revision envelope schema version",
            ));
        }
        validate_entry_revisions(&self.entries)?;
        if self
            .entries
            .windows(2)
            .any(|pair| compare_entry_identity(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(invalid_snapshot(
                "corpus entry revisions must be uniquely sorted by identity",
            ));
        }
        if self.digest != corpus_digest_unchecked(&self.entries) {
            return Err(invalid_snapshot(
                "corpus revision digest disagrees with its canonical entries",
            ));
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<String, KnowledgeError> {
        self.validate()?;
        let encoded = serde_json::to_string(self)
            .map_err(|error| KnowledgeError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_CORPUS_REVISION_ENVELOPE_BYTES {
            return Err(KnowledgeError::CorpusRevisionEnvelopeTooLarge {
                max_bytes: MAX_CORPUS_REVISION_ENVELOPE_BYTES,
                actual_bytes: encoded.len(),
            });
        }
        Ok(encoded)
    }

    pub fn from_canonical_json(value: &str) -> Result<Self, KnowledgeError> {
        if value.is_empty() || value.len() > MAX_CORPUS_REVISION_ENVELOPE_BYTES {
            return Err(KnowledgeError::CorpusRevisionEnvelopeTooLarge {
                max_bytes: MAX_CORPUS_REVISION_ENVELOPE_BYTES,
                actual_bytes: value.len(),
            });
        }
        let envelope = serde_json::from_str::<CorpusRevisionEnvelopeWire>(value)
            .map_err(|error| KnowledgeError::Serialization(error.to_string()))?
            .into_envelope()?;
        let canonical = envelope.canonical_json()?;
        if canonical != value {
            return Err(KnowledgeError::NonCanonicalEnvelope);
        }
        Ok(envelope)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusRevisionEnvelopeWire {
    schema_version: u16,
    digest: Sha256Digest,
    entries: Vec<EntryRevision>,
}

impl CorpusRevisionEnvelopeWire {
    fn into_envelope(self) -> Result<CorpusRevisionEnvelope, KnowledgeError> {
        let envelope = CorpusRevisionEnvelope {
            schema_version: self.schema_version,
            digest: self.digest,
            entries: self.entries,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

/// Complete scoring contribution for one query term in an included hit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermEvidence {
    token: String,
    query_frequency: u32,
    title_frequency: u32,
    content_frequency: u32,
    contribution: u64,
}

impl TermEvidence {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub const fn query_frequency(&self) -> u32 {
        self.query_frequency
    }

    pub const fn title_frequency(&self) -> u32 {
        self.title_frequency
    }

    pub const fn content_frequency(&self) -> u32 {
        self.content_frequency
    }

    pub const fn contribution(&self) -> u64 {
        self.contribution
    }

    fn validate(&self) -> Result<(), KnowledgeError> {
        let canonical_tokens = tokenize(&self.token);
        if canonical_tokens.len() != 1 || canonical_tokens[0] != self.token {
            return Err(invalid_snapshot(
                "matched term must be one canonical tokenizer token",
            ));
        }
        if self.query_frequency == 0 || (self.title_frequency == 0 && self.content_frequency == 0) {
            return Err(invalid_snapshot(
                "matched term frequencies must describe a real match",
            ));
        }
        let expected = term_contribution(
            self.query_frequency,
            self.title_frequency,
            self.content_frequency,
        )?;
        if self.contribution != expected {
            return Err(invalid_snapshot(
                "matched term contribution disagrees with integer scoring",
            ));
        }
        Ok(())
    }
}

/// A selected entry and the complete evidence needed to explain its score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionHit {
    selection_rank: u8,
    candidate_rank: u16,
    entry: EntryRevision,
    content_digest: Sha256Digest,
    score: u64,
    matched_terms: Vec<TermEvidence>,
}

impl SelectionHit {
    pub const fn selection_rank(&self) -> u8 {
        self.selection_rank
    }

    pub const fn candidate_rank(&self) -> u16 {
        self.candidate_rank
    }

    pub fn entry(&self) -> &EntryRevision {
        &self.entry
    }

    pub const fn content_digest(&self) -> Sha256Digest {
        self.content_digest
    }

    pub const fn score(&self) -> u64 {
        self.score
    }

    pub fn matched_terms(&self) -> &[TermEvidence] {
        &self.matched_terms
    }

    fn validate(&self) -> Result<(), KnowledgeError> {
        self.entry.validate()?;
        if self.selection_rank == 0 || self.candidate_rank == 0 || self.score == 0 {
            return Err(invalid_snapshot("hit ranks and score must be positive"));
        }
        if self.content_digest != self.entry.content_digest() {
            return Err(invalid_snapshot(
                "hit content digest disagrees with its immutable entry revision",
            ));
        }
        if self.matched_terms.is_empty() {
            return Err(invalid_snapshot(
                "a selected hit must contain term evidence",
            ));
        }
        if self.matched_terms.len() > MAX_QUERY_UNIQUE_TERMS {
            return Err(invalid_snapshot(
                "a selected hit exceeds the query unique-term limit",
            ));
        }
        let frequencies = entry_token_frequencies(&self.entry)?;
        let mut previous: Option<&str> = None;
        let mut score = 0_u64;
        for term in &self.matched_terms {
            term.validate()?;
            if previous.is_some_and(|value| value >= term.token.as_str()) {
                return Err(invalid_snapshot(
                    "matched term evidence must be uniquely sorted by token",
                ));
            }
            previous = Some(&term.token);
            if frequencies.title.get(&term.token).copied().unwrap_or(0) != term.title_frequency
                || frequencies.content.get(&term.token).copied().unwrap_or(0)
                    != term.content_frequency
            {
                return Err(invalid_snapshot(
                    "matched term frequencies disagree with the immutable entry revision",
                ));
            }
            score = score
                .checked_add(term.contribution)
                .ok_or(KnowledgeError::ArithmeticOverflow)?;
        }
        if score != self.score {
            return Err(invalid_snapshot(
                "hit score disagrees with its term contributions",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDisposition {
    Included,
    ContextBudget,
    HitLimit,
}

/// Stable ranked-candidate evidence, including candidates omitted in full.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidence {
    candidate_rank: u16,
    entry_id: String,
    revision: String,
    content_digest: Sha256Digest,
    score: u64,
    disposition: CandidateDisposition,
}

impl CandidateEvidence {
    pub const fn candidate_rank(&self) -> u16 {
        self.candidate_rank
    }

    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub const fn content_digest(&self) -> Sha256Digest {
        self.content_digest
    }

    pub const fn score(&self) -> u64 {
        self.score
    }

    pub const fn disposition(&self) -> CandidateDisposition {
        self.disposition
    }
}

/// Aggregate evidence for the complete bounded input and ranked match set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionEvidence {
    input_entry_revisions: u16,
    matched_entry_revisions: u16,
    unmatched_entry_revisions: u16,
    candidates: Vec<CandidateEvidence>,
}

impl SelectionEvidence {
    pub const fn input_entry_revisions(&self) -> u16 {
        self.input_entry_revisions
    }

    pub const fn matched_entry_revisions(&self) -> u16 {
        self.matched_entry_revisions
    }

    pub const fn unmatched_entry_revisions(&self) -> u16 {
        self.unmatched_entry_revisions
    }

    pub fn candidates(&self) -> &[CandidateEvidence] {
        &self.candidates
    }
}

/// Exact durable output of one governed selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SelectionSnapshot {
    schema_version: u16,
    tokenizer_revision: String,
    scoring_revision: String,
    renderer_revision: String,
    query_digest: Sha256Digest,
    corpus_digest: Sha256Digest,
    context_digest: Sha256Digest,
    context_bytes: u32,
    canonical_context: String,
    hits: Vec<SelectionHit>,
    evidence: SelectionEvidence,
}

impl SelectionSnapshot {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn tokenizer_revision(&self) -> &str {
        &self.tokenizer_revision
    }

    pub fn scoring_revision(&self) -> &str {
        &self.scoring_revision
    }

    pub fn renderer_revision(&self) -> &str {
        &self.renderer_revision
    }

    pub const fn query_digest(&self) -> Sha256Digest {
        self.query_digest
    }

    pub const fn corpus_digest(&self) -> Sha256Digest {
        self.corpus_digest
    }

    pub const fn context_digest(&self) -> Sha256Digest {
        self.context_digest
    }

    pub const fn context_bytes(&self) -> u32 {
        self.context_bytes
    }

    pub fn canonical_context(&self) -> &str {
        &self.canonical_context
    }

    pub fn hits(&self) -> &[SelectionHit] {
        &self.hits
    }

    pub fn evidence(&self) -> &SelectionEvidence {
        &self.evidence
    }

    pub fn matches_query(&self, query: &str) -> Result<bool, KnowledgeError> {
        Ok(self.query_digest == query_digest(query)?)
    }

    /// Validate the snapshot against the exact user query that selected it.
    ///
    /// The durable query digest proves byte identity, while this additional
    /// check recomputes every persisted query-term frequency. Storage should
    /// use this method when it can read the immutable Session user message.
    pub fn validate_for_query(&self, query: &str) -> Result<(), KnowledgeError> {
        self.validate()?;
        let query_frequencies = validated_query_frequencies(query)?;
        if self.query_digest != domain_digest(QUERY_DIGEST_DOMAIN, query.as_bytes()) {
            return Err(invalid_snapshot(
                "query digest disagrees with the immutable user message",
            ));
        }
        for hit in &self.hits {
            let expected = score_entry(&hit.entry, &query_frequencies)?.ok_or_else(|| {
                invalid_snapshot("selected entry no longer matches the immutable user message")
            })?;
            if expected.content_digest != hit.content_digest
                || expected.score != hit.score
                || expected.matched_terms != hit.matched_terms
            {
                return Err(invalid_snapshot(
                    "selected entry evidence disagrees with the immutable user message",
                ));
            }
        }
        Ok(())
    }

    /// Prove the complete selection against the immutable corpus revision.
    ///
    /// This re-runs the deterministic selector and compares every hit,
    /// disposition, score, digest, and rendered byte. It is intended for
    /// admission and deep-integrity checks over already-local immutable entry
    /// revisions; provider execution must continue to consume the persisted
    /// snapshot and must never retrieve live knowledge again.
    pub fn validate_for_selection(
        &self,
        query: &str,
        entries: &[EntryRevision],
    ) -> Result<(), KnowledgeError> {
        self.validate_for_query(query)?;
        if self.corpus_digest != corpus_digest(entries)? {
            return Err(invalid_snapshot(
                "selection disagrees with the exact immutable corpus revision",
            ));
        }
        let expected = select(query, entries)?;
        if self != &expected {
            return Err(invalid_snapshot(
                "selection disagrees with the immutable corpus revision",
            ));
        }
        Ok(())
    }

    /// Encode the complete snapshot payload in canonical JSON form.
    pub fn canonical_payload_json(&self) -> Result<String, KnowledgeError> {
        self.validate()?;
        let encoded = serde_json::to_string(self)
            .map_err(|error| KnowledgeError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_SELECTION_SNAPSHOT_BYTES {
            return Err(KnowledgeError::SelectionSnapshotTooLarge {
                max_bytes: MAX_SELECTION_SNAPSHOT_BYTES,
                actual_bytes: encoded.len(),
            });
        }
        Ok(encoded)
    }

    /// Digest the complete canonical snapshot payload for durable binding.
    ///
    /// Unlike [`Self::context_digest`], this covers the query, revisions,
    /// scores, dispositions, evidence, and exact rendered context.
    pub fn snapshot_digest(&self) -> Result<Sha256Digest, KnowledgeError> {
        let encoded = self.canonical_payload_json()?;
        Ok(domain_digest(
            SELECTION_SNAPSHOT_DIGEST_DOMAIN,
            encoded.as_bytes(),
        ))
    }

    /// Decode and validate a durable snapshot. Whitespace, key reordering, or
    /// any other non-canonical but semantically equivalent JSON is rejected.
    pub fn from_canonical_payload_json(value: &str) -> Result<Self, KnowledgeError> {
        if value.is_empty() || value.len() > MAX_SELECTION_SNAPSHOT_BYTES {
            return Err(KnowledgeError::SelectionSnapshotTooLarge {
                max_bytes: MAX_SELECTION_SNAPSHOT_BYTES,
                actual_bytes: value.len(),
            });
        }
        let snapshot = serde_json::from_str::<SelectionSnapshotWire>(value)
            .map_err(|error| KnowledgeError::Serialization(error.to_string()))?
            .into_snapshot()?;
        let canonical = snapshot.canonical_payload_json()?;
        if canonical != value {
            return Err(KnowledgeError::NonCanonicalEnvelope);
        }
        Ok(snapshot)
    }

    /// Recheck all self-contained snapshot invariants without consulting live
    /// knowledge or the original query.
    pub fn validate(&self) -> Result<(), KnowledgeError> {
        if self.schema_version != SELECTION_SNAPSHOT_SCHEMA_VERSION
            || self.tokenizer_revision != TOKENIZER_REVISION
            || self.scoring_revision != SCORING_REVISION
            || self.renderer_revision != CONTEXT_RENDERER_REVISION
        {
            return Err(invalid_snapshot("unsupported selection contract revision"));
        }
        if self.hits.len() > MAX_SELECTION_HITS {
            return Err(invalid_snapshot("snapshot exceeds the hit limit"));
        }
        let mut observed_query_frequencies = BTreeMap::<&str, u32>::new();
        for (index, hit) in self.hits.iter().enumerate() {
            hit.validate()?;
            for term in &hit.matched_terms {
                if observed_query_frequencies
                    .insert(&term.token, term.query_frequency)
                    .is_some_and(|frequency| frequency != term.query_frequency)
                {
                    return Err(invalid_snapshot(
                        "query term frequency evidence must agree across selected hits",
                    ));
                }
            }
            let expected_rank =
                u8::try_from(index + 1).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
            if hit.selection_rank != expected_rank {
                return Err(invalid_snapshot("selection ranks must be contiguous"));
            }
            if index > 0 && self.hits[index - 1].candidate_rank >= hit.candidate_rank {
                return Err(invalid_snapshot(
                    "selected hits must preserve candidate ranking order",
                ));
            }
        }

        validate_selection_evidence(&self.evidence, &self.hits)?;
        let canonical = render_context_unbounded(&self.hits);
        if canonical.len() > MAX_CANONICAL_CONTEXT_BYTES {
            return Err(invalid_snapshot("canonical context exceeds its byte limit"));
        }
        if canonical != self.canonical_context {
            return Err(invalid_snapshot(
                "canonical context disagrees with the complete selected entries",
            ));
        }
        let context_bytes =
            u32::try_from(canonical.len()).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
        if self.context_bytes != context_bytes {
            return Err(invalid_snapshot("context byte evidence is inconsistent"));
        }
        if self.context_digest != canonical_context_digest(&canonical) {
            return Err(invalid_snapshot("canonical context digest is inconsistent"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionSnapshotWire {
    schema_version: u16,
    tokenizer_revision: String,
    scoring_revision: String,
    renderer_revision: String,
    query_digest: Sha256Digest,
    corpus_digest: Sha256Digest,
    context_digest: Sha256Digest,
    context_bytes: u32,
    canonical_context: String,
    hits: Vec<SelectionHit>,
    evidence: SelectionEvidence,
}

impl SelectionSnapshotWire {
    fn into_snapshot(self) -> Result<SelectionSnapshot, KnowledgeError> {
        let snapshot = SelectionSnapshot {
            schema_version: self.schema_version,
            tokenizer_revision: self.tokenizer_revision,
            scoring_revision: self.scoring_revision,
            renderer_revision: self.renderer_revision,
            query_digest: self.query_digest,
            corpus_digest: self.corpus_digest,
            context_digest: self.context_digest,
            context_bytes: self.context_bytes,
            canonical_context: self.canonical_context,
            hits: self.hits,
            evidence: self.evidence,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

/// Immutable, digest-bearing durable representation of one selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SelectionSnapshotEnvelope {
    schema_version: u16,
    digest: Sha256Digest,
    snapshot: SelectionSnapshot,
}

impl SelectionSnapshotEnvelope {
    pub fn new(snapshot: SelectionSnapshot) -> Result<Self, KnowledgeError> {
        snapshot.validate()?;
        let digest = snapshot.snapshot_digest()?;
        Ok(Self {
            schema_version: SELECTION_SNAPSHOT_ENVELOPE_SCHEMA_VERSION,
            digest,
            snapshot,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub fn snapshot(&self) -> &SelectionSnapshot {
        &self.snapshot
    }

    pub fn into_snapshot(self) -> SelectionSnapshot {
        self.snapshot
    }

    pub fn validate(&self) -> Result<(), KnowledgeError> {
        if self.schema_version != SELECTION_SNAPSHOT_ENVELOPE_SCHEMA_VERSION {
            return Err(invalid_snapshot(
                "unsupported selection snapshot envelope revision",
            ));
        }
        self.snapshot.validate()?;
        if self.digest != self.snapshot.snapshot_digest()? {
            return Err(invalid_snapshot(
                "selection snapshot digest disagrees with its canonical payload",
            ));
        }
        Ok(())
    }

    pub fn validate_for_selection(
        &self,
        query: &str,
        entries: &[EntryRevision],
    ) -> Result<(), KnowledgeError> {
        self.validate()?;
        self.snapshot.validate_for_selection(query, entries)
    }

    /// Encode the digest and snapshot payload in their only durable JSON form.
    pub fn canonical_json(&self) -> Result<String, KnowledgeError> {
        self.validate()?;
        let encoded = serde_json::to_string(self)
            .map_err(|error| KnowledgeError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_SELECTION_SNAPSHOT_BYTES {
            return Err(KnowledgeError::SelectionSnapshotTooLarge {
                max_bytes: MAX_SELECTION_SNAPSHOT_BYTES,
                actual_bytes: encoded.len(),
            });
        }
        Ok(encoded)
    }

    pub fn from_canonical_json(value: &str) -> Result<Self, KnowledgeError> {
        if value.is_empty() || value.len() > MAX_SELECTION_SNAPSHOT_BYTES {
            return Err(KnowledgeError::SelectionSnapshotTooLarge {
                max_bytes: MAX_SELECTION_SNAPSHOT_BYTES,
                actual_bytes: value.len(),
            });
        }
        let envelope = serde_json::from_str::<SelectionSnapshotEnvelopeWire>(value)
            .map_err(|error| KnowledgeError::Serialization(error.to_string()))?
            .into_envelope()?;
        let canonical = envelope.canonical_json()?;
        if canonical != value {
            return Err(KnowledgeError::NonCanonicalEnvelope);
        }
        Ok(envelope)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionSnapshotEnvelopeWire {
    schema_version: u16,
    digest: Sha256Digest,
    snapshot: SelectionSnapshotWire,
}

impl SelectionSnapshotEnvelopeWire {
    fn into_envelope(self) -> Result<SelectionSnapshotEnvelope, KnowledgeError> {
        let envelope = SelectionSnapshotEnvelope {
            schema_version: self.schema_version,
            digest: self.digest,
            snapshot: self.snapshot.into_snapshot()?,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnowledgeError {
    InvalidField {
        field: &'static str,
        reason: String,
    },
    InvalidDigest,
    TooManyEntryRevisions {
        max: usize,
        actual: usize,
    },
    AggregateEntriesTooLarge {
        max_bytes: usize,
        actual_bytes: usize,
    },
    DuplicateEntryRevision {
        entry_id: String,
        revision: String,
    },
    QueryHasNoTokens,
    TooManyQueryTerms {
        max: usize,
        actual: usize,
    },
    TooManyEntryTerms {
        entry_id: String,
        max: usize,
        actual: usize,
    },
    CanonicalContextTooLarge {
        max_bytes: usize,
        actual_bytes: usize,
    },
    SelectionSnapshotTooLarge {
        max_bytes: usize,
        actual_bytes: usize,
    },
    CorpusRevisionEnvelopeTooLarge {
        max_bytes: usize,
        actual_bytes: usize,
    },
    NonCanonicalEnvelope,
    Serialization(String),
    ArithmeticOverflow,
    InvalidSnapshot(String),
}

impl fmt::Display for KnowledgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::InvalidDigest => formatter.write_str("invalid lowercase SHA-256 digest"),
            Self::TooManyEntryRevisions { max, actual } => {
                write!(
                    formatter,
                    "knowledge input has {actual} revisions; maximum is {max}"
                )
            }
            Self::AggregateEntriesTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "knowledge input uses {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::DuplicateEntryRevision { entry_id, revision } => write!(
                formatter,
                "duplicate knowledge entry revision `{entry_id}` at `{revision}`"
            ),
            Self::QueryHasNoTokens => {
                formatter.write_str("knowledge query does not contain a searchable token")
            }
            Self::TooManyQueryTerms { max, actual } => write!(
                formatter,
                "knowledge query has {actual} unique terms; maximum is {max}"
            ),
            Self::TooManyEntryTerms {
                entry_id,
                max,
                actual,
            } => write!(
                formatter,
                "knowledge entry `{entry_id}` has {actual} unique terms; maximum is {max}"
            ),
            Self::CanonicalContextTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "canonical knowledge context uses {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::SelectionSnapshotTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "knowledge selection snapshot uses {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::CorpusRevisionEnvelopeTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "knowledge corpus revision envelope uses {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::NonCanonicalEnvelope => {
                formatter.write_str("knowledge durable artifact JSON is not canonical")
            }
            Self::Serialization(reason) => {
                write!(
                    formatter,
                    "knowledge durable artifact serialization failed: {reason}"
                )
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("knowledge selection arithmetic overflowed")
            }
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "invalid knowledge durable artifact: {reason}")
            }
        }
    }
}

impl std::error::Error for KnowledgeError {}

/// Tokenize text with the stable v1 contract.
///
/// Consecutive ASCII letters and digits form one lowercased token. Every
/// non-ASCII Unicode scalar that is not one of the explicitly fixed whitespace
/// scalars forms one exact token. All other ASCII bytes are separators. This
/// deliberately avoids locale, stemming, Unicode database versions, and
/// floating-point behavior.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut ascii = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            ascii.push(character.to_ascii_lowercase());
            continue;
        }
        if !ascii.is_empty() {
            tokens.push(std::mem::take(&mut ascii));
        }
        if !character.is_ascii() && !is_fixed_whitespace(character) {
            tokens.push(character.to_string());
        }
    }
    if !ascii.is_empty() {
        tokens.push(ascii);
    }
    tokens
}

/// Digest the exact validated query bytes, not a normalized token stream.
pub fn query_digest(query: &str) -> Result<Sha256Digest, KnowledgeError> {
    validate_query(query)?;
    Ok(domain_digest(QUERY_DIGEST_DOMAIN, query.as_bytes()))
}

/// Digest the exact immutable corpus revision independent of caller order.
///
/// Every identity, title, and content byte is length-delimited in the digest
/// material. Replacing even an unmatched entry therefore changes the corpus
/// binding carried by a selection snapshot.
pub fn corpus_digest(entries: &[EntryRevision]) -> Result<Sha256Digest, KnowledgeError> {
    validate_entry_revisions(entries)?;
    Ok(corpus_digest_unchecked(entries))
}

/// Digest exact immutable entry content bytes.
pub fn content_digest(content: &str) -> Sha256Digest {
    domain_digest(ENTRY_CONTENT_DIGEST_DOMAIN, content.as_bytes())
}

/// Digest exact canonical-context bytes.
pub fn canonical_context_digest(context: &str) -> Sha256Digest {
    domain_digest(CONTEXT_DIGEST_DOMAIN, context.as_bytes())
}

/// Select a deterministic, bounded knowledge context from immutable revisions.
pub fn select(query: &str, entries: &[EntryRevision]) -> Result<SelectionSnapshot, KnowledgeError> {
    let query_frequencies = validated_query_frequencies(query)?;
    validate_entry_revisions(entries)?;
    let corpus_digest = corpus_digest_unchecked(entries);

    let mut candidates = Vec::new();
    for entry in entries {
        if let Some(candidate) = score_entry(entry, &query_frequencies)? {
            candidates.push(candidate);
        }
    }
    candidates.sort_by(compare_candidates);

    let mut hits = Vec::with_capacity(MAX_SELECTION_HITS.min(candidates.len()));
    let mut candidate_evidence = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.into_iter().enumerate() {
        let candidate_rank =
            u16::try_from(index + 1).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
        let disposition = if hits.len() >= MAX_SELECTION_HITS {
            CandidateDisposition::HitLimit
        } else {
            let selection_rank =
                u8::try_from(hits.len() + 1).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
            let hit = SelectionHit {
                selection_rank,
                candidate_rank,
                entry: candidate.entry.clone(),
                content_digest: candidate.content_digest,
                score: candidate.score,
                matched_terms: candidate.matched_terms.clone(),
            };
            hits.push(hit);
            if render_context_unbounded(&hits).len() <= MAX_CANONICAL_CONTEXT_BYTES {
                CandidateDisposition::Included
            } else {
                hits.pop();
                CandidateDisposition::ContextBudget
            }
        };
        candidate_evidence.push(CandidateEvidence {
            candidate_rank,
            entry_id: candidate.entry.entry_id,
            revision: candidate.entry.revision,
            content_digest: candidate.content_digest,
            score: candidate.score,
            disposition,
        });
    }

    let canonical_context = render_context_unbounded(&hits);
    debug_assert!(canonical_context.len() <= MAX_CANONICAL_CONTEXT_BYTES);
    let input_entry_revisions =
        u16::try_from(entries.len()).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
    let matched_entry_revisions =
        u16::try_from(candidate_evidence.len()).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
    let unmatched_entry_revisions = input_entry_revisions
        .checked_sub(matched_entry_revisions)
        .ok_or(KnowledgeError::ArithmeticOverflow)?;
    let context_bytes =
        u32::try_from(canonical_context.len()).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
    let snapshot = SelectionSnapshot {
        schema_version: SELECTION_SNAPSHOT_SCHEMA_VERSION,
        tokenizer_revision: TOKENIZER_REVISION.into(),
        scoring_revision: SCORING_REVISION.into(),
        renderer_revision: CONTEXT_RENDERER_REVISION.into(),
        query_digest: domain_digest(QUERY_DIGEST_DOMAIN, query.as_bytes()),
        corpus_digest,
        context_digest: canonical_context_digest(&canonical_context),
        context_bytes,
        canonical_context,
        hits,
        evidence: SelectionEvidence {
            input_entry_revisions,
            matched_entry_revisions,
            unmatched_entry_revisions,
            candidates: candidate_evidence,
        },
    };
    snapshot.validate_for_query(query)?;
    let _ = SelectionSnapshotEnvelope::new(snapshot.clone())?.canonical_json()?;
    Ok(snapshot)
}

/// Alias that makes the returned artifact explicit at integration call sites.
pub fn select_context(
    query: &str,
    entries: &[EntryRevision],
) -> Result<SelectionSnapshot, KnowledgeError> {
    select(query, entries)
}

/// Render included hits as canonical compact JSON.
///
/// The output contains every selected title and content byte after JSON
/// escaping; it never truncates an entry. Oversized or structurally invalid hit
/// sets fail instead of returning a partial context.
pub fn render_canonical_context(hits: &[SelectionHit]) -> Result<String, KnowledgeError> {
    if hits.len() > MAX_SELECTION_HITS {
        return Err(KnowledgeError::TooManyEntryRevisions {
            max: MAX_SELECTION_HITS,
            actual: hits.len(),
        });
    }
    for (index, hit) in hits.iter().enumerate() {
        hit.validate()?;
        let rank = u8::try_from(index + 1).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
        if hit.selection_rank != rank {
            return Err(invalid_snapshot("selection ranks must be contiguous"));
        }
    }
    let output = render_context_unbounded(hits);
    if output.len() > MAX_CANONICAL_CONTEXT_BYTES {
        return Err(KnowledgeError::CanonicalContextTooLarge {
            max_bytes: MAX_CANONICAL_CONTEXT_BYTES,
            actual_bytes: output.len(),
        });
    }
    Ok(output)
}

#[derive(Clone)]
struct Candidate {
    entry: EntryRevision,
    content_digest: Sha256Digest,
    score: u64,
    matched_terms: Vec<TermEvidence>,
}

struct EntryTokenFrequencies {
    title: TermFrequencies,
    content: TermFrequencies,
}

fn score_entry(
    entry: &EntryRevision,
    query: &TermFrequencies,
) -> Result<Option<Candidate>, KnowledgeError> {
    let frequencies = entry_token_frequencies(entry)?;
    let mut score = 0_u64;
    let mut matched_terms = Vec::new();
    for (token, query_frequency) in query {
        let title_frequency = frequencies.title.get(token).copied().unwrap_or(0);
        let content_frequency = frequencies.content.get(token).copied().unwrap_or(0);
        if title_frequency == 0 && content_frequency == 0 {
            continue;
        }
        let contribution = term_contribution(*query_frequency, title_frequency, content_frequency)?;
        score = score
            .checked_add(contribution)
            .ok_or(KnowledgeError::ArithmeticOverflow)?;
        matched_terms.push(TermEvidence {
            token: token.clone(),
            query_frequency: *query_frequency,
            title_frequency,
            content_frequency,
            contribution,
        });
    }
    if score == 0 {
        return Ok(None);
    }
    Ok(Some(Candidate {
        entry: entry.clone(),
        content_digest: entry.content_digest(),
        score,
        matched_terms,
    }))
}

fn entry_token_frequencies(entry: &EntryRevision) -> Result<EntryTokenFrequencies, KnowledgeError> {
    let title = token_frequencies(tokenize(&entry.title));
    let content = token_frequencies(tokenize(&entry.content));
    let unique_terms = title
        .keys()
        .chain(content.keys())
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if unique_terms.len() > MAX_ENTRY_UNIQUE_TERMS {
        return Err(KnowledgeError::TooManyEntryTerms {
            entry_id: entry.entry_id.clone(),
            max: MAX_ENTRY_UNIQUE_TERMS,
            actual: unique_terms.len(),
        });
    }
    Ok(EntryTokenFrequencies { title, content })
}

fn term_contribution(
    query_frequency: u32,
    title_frequency: u32,
    content_frequency: u32,
) -> Result<u64, KnowledgeError> {
    let title_score = u64::from(title_frequency)
        .checked_mul(TITLE_TOKEN_WEIGHT)
        .ok_or(KnowledgeError::ArithmeticOverflow)?;
    let content_score = u64::from(content_frequency)
        .checked_mul(CONTENT_TOKEN_WEIGHT)
        .ok_or(KnowledgeError::ArithmeticOverflow)?;
    title_score
        .checked_add(content_score)
        .and_then(|value| value.checked_mul(u64::from(query_frequency)))
        .ok_or(KnowledgeError::ArithmeticOverflow)
}

fn compare_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.entry.entry_id.cmp(&right.entry.entry_id))
        .then_with(|| left.entry.revision.cmp(&right.entry.revision))
        .then_with(|| left.content_digest.cmp(&right.content_digest))
}

fn token_frequencies(tokens: Vec<String>) -> TermFrequencies {
    let mut frequencies = BTreeMap::new();
    for token in tokens {
        let frequency = frequencies.entry(token).or_insert(0_u32);
        *frequency = frequency
            .checked_add(1)
            .expect("bounded UTF-8 input cannot contain u32::MAX tokens");
    }
    frequencies
}

fn validate_selection_evidence(
    evidence: &SelectionEvidence,
    hits: &[SelectionHit],
) -> Result<(), KnowledgeError> {
    if usize::from(evidence.input_entry_revisions) > MAX_ENTRY_REVISIONS {
        return Err(invalid_snapshot(
            "evidence exceeds the input revision limit",
        ));
    }
    let observed_input = evidence
        .matched_entry_revisions
        .checked_add(evidence.unmatched_entry_revisions)
        .ok_or(KnowledgeError::ArithmeticOverflow)?;
    if observed_input != evidence.input_entry_revisions
        || usize::from(evidence.matched_entry_revisions) != evidence.candidates.len()
    {
        return Err(invalid_snapshot(
            "selection evidence counts are inconsistent",
        ));
    }

    let mut included = 0_usize;
    let mut hit_index = 0_usize;
    let mut candidate_identities = BTreeSet::new();
    for (index, candidate) in evidence.candidates.iter().enumerate() {
        let expected_rank =
            u16::try_from(index + 1).map_err(|_| KnowledgeError::ArithmeticOverflow)?;
        if candidate.candidate_rank != expected_rank || candidate.score == 0 {
            return Err(invalid_snapshot(
                "candidate evidence ranks and scores must be positive and contiguous",
            ));
        }
        validate_identifier(
            "candidate.entry_id",
            &candidate.entry_id,
            MAX_ENTRY_ID_BYTES,
        )?;
        validate_identifier(
            "candidate.revision",
            &candidate.revision,
            MAX_ENTRY_REVISION_BYTES,
        )?;
        if !candidate_identities.insert((candidate.entry_id.as_str(), candidate.revision.as_str()))
        {
            return Err(invalid_snapshot(
                "candidate evidence contains a duplicate entry revision",
            ));
        }
        if index > 0 {
            let previous = &evidence.candidates[index - 1];
            if compare_candidate_evidence(previous, candidate) == Ordering::Greater {
                return Err(invalid_snapshot(
                    "candidate evidence does not use the stable ranking order",
                ));
            }
        }
        match candidate.disposition {
            CandidateDisposition::Included => {
                if included >= MAX_SELECTION_HITS {
                    return Err(invalid_snapshot("evidence includes too many hits"));
                }
                let hit = hits.get(hit_index).ok_or_else(|| {
                    invalid_snapshot("included candidate is missing its selected hit")
                })?;
                if hit.candidate_rank != candidate.candidate_rank
                    || hit.entry.entry_id != candidate.entry_id
                    || hit.entry.revision != candidate.revision
                    || hit.content_digest != candidate.content_digest
                    || hit.score != candidate.score
                {
                    return Err(invalid_snapshot(
                        "included candidate disagrees with its selected hit",
                    ));
                }
                included += 1;
                hit_index += 1;
            }
            CandidateDisposition::ContextBudget => {
                if included >= MAX_SELECTION_HITS {
                    return Err(invalid_snapshot(
                        "context-budget evidence cannot follow a full hit set",
                    ));
                }
            }
            CandidateDisposition::HitLimit => {
                if included != MAX_SELECTION_HITS {
                    return Err(invalid_snapshot(
                        "hit-limit evidence requires six earlier included hits",
                    ));
                }
            }
        }
    }
    if included != hits.len() || hit_index != hits.len() {
        return Err(invalid_snapshot(
            "selected hit count disagrees with candidate evidence",
        ));
    }
    Ok(())
}

fn compare_candidate_evidence(left: &CandidateEvidence, right: &CandidateEvidence) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.entry_id.cmp(&right.entry_id))
        .then_with(|| left.revision.cmp(&right.revision))
        .then_with(|| left.content_digest.cmp(&right.content_digest))
}

fn render_context_unbounded(hits: &[SelectionHit]) -> String {
    let mut output = String::from("{\"schema_version\":1,\"renderer\":");
    push_json_string(&mut output, CONTEXT_RENDERER_REVISION);
    output.push_str(",\"entries\":[");
    for (index, hit) in hits.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"entry_id\":");
        push_json_string(&mut output, &hit.entry.entry_id);
        output.push_str(",\"revision\":");
        push_json_string(&mut output, &hit.entry.revision);
        output.push_str(",\"content_digest\":");
        push_json_string(&mut output, &hit.content_digest.to_hex());
        output.push_str(",\"title\":");
        push_json_string(&mut output, &hit.entry.title);
        output.push_str(",\"content\":");
        push_json_string(&mut output, &hit.entry.content);
        output.push('}');
    }
    output.push_str("]}");
    output
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if is_fixed_control(value) => {
                let code = u32::from(value);
                output.push_str("\\u");
                output.push(encode_hex(
                    u8::try_from((code >> 12) & 0x0f).expect("nibble"),
                ));
                output.push(encode_hex(
                    u8::try_from((code >> 8) & 0x0f).expect("nibble"),
                ));
                output.push(encode_hex(
                    u8::try_from((code >> 4) & 0x0f).expect("nibble"),
                ));
                output.push(encode_hex(u8::try_from(code & 0x0f).expect("nibble")));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

fn validate_query(query: &str) -> Result<(), KnowledgeError> {
    validate_text_bytes("query", query, MAX_QUERY_BYTES)?;
    if query.chars().all(is_fixed_whitespace) {
        return Err(invalid_field("query", "cannot be blank"));
    }
    if query.chars().any(is_disallowed_text_control) {
        return Err(invalid_field(
            "query",
            "cannot contain controls other than tab or line breaks",
        ));
    }
    if tokenize(query).is_empty() {
        return Err(KnowledgeError::QueryHasNoTokens);
    }
    Ok(())
}

fn validated_query_frequencies(query: &str) -> Result<TermFrequencies, KnowledgeError> {
    validate_query(query)?;
    let frequencies = token_frequencies(tokenize(query));
    if frequencies.len() > MAX_QUERY_UNIQUE_TERMS {
        return Err(KnowledgeError::TooManyQueryTerms {
            max: MAX_QUERY_UNIQUE_TERMS,
            actual: frequencies.len(),
        });
    }
    Ok(frequencies)
}

fn validate_entry_revisions(entries: &[EntryRevision]) -> Result<(), KnowledgeError> {
    if entries.len() > MAX_ENTRY_REVISIONS {
        return Err(KnowledgeError::TooManyEntryRevisions {
            max: MAX_ENTRY_REVISIONS,
            actual: entries.len(),
        });
    }

    let mut aggregate_bytes = 0_usize;
    let mut identities = BTreeSet::<(&str, &str)>::new();
    for entry in entries {
        entry.validate()?;
        let entry_bytes = entry
            .entry_id
            .len()
            .checked_add(entry.revision.len())
            .and_then(|value| value.checked_add(entry.title.len()))
            .and_then(|value| value.checked_add(entry.content.len()))
            .ok_or(KnowledgeError::ArithmeticOverflow)?;
        aggregate_bytes = aggregate_bytes
            .checked_add(entry_bytes)
            .ok_or(KnowledgeError::ArithmeticOverflow)?;
        if !identities.insert((&entry.entry_id, &entry.revision)) {
            return Err(KnowledgeError::DuplicateEntryRevision {
                entry_id: entry.entry_id.clone(),
                revision: entry.revision.clone(),
            });
        }
    }
    if aggregate_bytes > MAX_AGGREGATE_ENTRY_BYTES {
        return Err(KnowledgeError::AggregateEntriesTooLarge {
            max_bytes: MAX_AGGREGATE_ENTRY_BYTES,
            actual_bytes: aggregate_bytes,
        });
    }
    Ok(())
}

fn corpus_digest_unchecked(entries: &[EntryRevision]) -> Sha256Digest {
    let mut sorted = entries.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| compare_entry_identity(left, right));

    let mut material = Vec::new();
    material.extend_from_slice(
        &u64::try_from(sorted.len())
            .expect("bounded corpus length fits in u64")
            .to_be_bytes(),
    );
    for entry in sorted {
        for field in [
            entry.entry_id.as_bytes(),
            entry.revision.as_bytes(),
            entry.title.as_bytes(),
            entry.content.as_bytes(),
        ] {
            material.extend_from_slice(
                &u64::try_from(field.len())
                    .expect("bounded entry field length fits in u64")
                    .to_be_bytes(),
            );
            material.extend_from_slice(field);
        }
    }
    domain_digest(CORPUS_DIGEST_DOMAIN, &material)
}

fn compare_entry_identity(left: &EntryRevision, right: &EntryRevision) -> Ordering {
    left.entry_id
        .cmp(&right.entry_id)
        .then_with(|| left.revision.cmp(&right.revision))
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), KnowledgeError> {
    validate_text_bytes(field, value, max_bytes)?;
    if value
        .chars()
        .any(|character| is_fixed_whitespace(character) || is_fixed_control(character))
    {
        return Err(invalid_field(
            field,
            "cannot contain whitespace or control characters",
        ));
    }
    Ok(())
}

fn validate_title(title: &str) -> Result<(), KnowledgeError> {
    validate_text_bytes("title", title, MAX_ENTRY_TITLE_BYTES)?;
    if title.chars().all(is_fixed_whitespace) {
        return Err(invalid_field("title", "cannot be blank"));
    }
    if title.chars().next().is_some_and(is_fixed_whitespace)
        || title.chars().next_back().is_some_and(is_fixed_whitespace)
    {
        return Err(invalid_field(
            "title",
            "cannot have leading or trailing whitespace",
        ));
    }
    if title.chars().any(is_fixed_control) {
        return Err(invalid_field("title", "cannot contain control characters"));
    }
    Ok(())
}

fn validate_content(content: &str) -> Result<(), KnowledgeError> {
    validate_text_bytes("content", content, MAX_ENTRY_CONTENT_BYTES)?;
    if content.chars().all(is_fixed_whitespace) {
        return Err(invalid_field("content", "cannot be blank"));
    }
    if content.chars().any(is_disallowed_text_control) {
        return Err(invalid_field(
            "content",
            "cannot contain controls other than tab or line breaks",
        ));
    }
    Ok(())
}

fn validate_text_bytes(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), KnowledgeError> {
    if value.is_empty() {
        return Err(invalid_field(field, "cannot be empty"));
    }
    if value.len() > max_bytes {
        return Err(invalid_field(
            field,
            format!("cannot exceed {max_bytes} UTF-8 bytes"),
        ));
    }
    Ok(())
}

fn invalid_field(field: &'static str, reason: impl Into<String>) -> KnowledgeError {
    KnowledgeError::InvalidField {
        field,
        reason: reason.into(),
    }
}

fn invalid_snapshot(reason: impl Into<String>) -> KnowledgeError {
    KnowledgeError::InvalidSnapshot(reason.into())
}

const fn is_fixed_control(character: char) -> bool {
    let code = character as u32;
    code <= 0x1f || (code >= 0x7f && code <= 0x9f)
}

const fn is_disallowed_text_control(character: char) -> bool {
    is_fixed_control(character) && !matches!(character, '\t' | '\n' | '\r')
}

const fn is_fixed_whitespace(character: char) -> bool {
    matches!(
        character as u32,
        0x0009..=0x000d
            | 0x0020
            | 0x0085
            | 0x00a0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
    )
}

fn domain_digest(domain: &[u8], content: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(
        u64::try_from(domain.len())
            .expect("digest domain length fits in u64")
            .to_be_bytes(),
    );
    digest.update(domain);
    digest.update(
        u64::try_from(content.len())
            .expect("in-memory content length fits in u64")
            .to_be_bytes(),
    );
    digest.update(content);
    Sha256Digest(digest.finalize().into())
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

const fn encode_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, title: &str, content: &str) -> EntryRevision {
        EntryRevision::new(id, "r1", title, content).unwrap()
    }

    #[test]
    fn sha256_matches_standard_vectors_and_hex_is_strict() {
        let mut empty = Sha256::new();
        empty.update([]);
        assert_eq!(
            Sha256Digest(empty.finalize().into()).to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut abc = Sha256::new();
        abc.update(b"a");
        abc.update(b"bc");
        let digest = Sha256Digest(abc.finalize().into());
        assert_eq!(
            digest.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Sha256Digest::from_hex(&digest.to_hex()).unwrap(), digest);
        assert!(Sha256Digest::from_hex(&digest.to_hex().to_uppercase()).is_err());
    }

    #[test]
    fn tokenizer_is_ascii_case_folded_and_unicode_scalar_exact() {
        assert_eq!(
            tokenize("Rust RUST-42 café　中文🙂"),
            ["rust", "rust", "42", "caf", "é", "中", "文", "🙂"]
        );
        assert_eq!(tokenize("A_B/C.D"), ["a", "b", "c", "d"]);
    }

    #[test]
    fn entry_revision_is_byte_bounded_and_control_safe() {
        assert!(EntryRevision::new("entry-1", "rev-1", "标题", "第一行\n第二行").is_ok());
        assert!(EntryRevision::new("entry 1", "rev-1", "Title", "Body").is_err());
        assert!(EntryRevision::new("entry-1", "rev-1", " Title", "Body").is_err());
        assert!(EntryRevision::new("entry-1", "rev-1", "Title", "bad\0body").is_err());
        assert!(
            EntryRevision::new(
                "entry-1",
                "rev-1",
                "🙂".repeat(MAX_ENTRY_TITLE_BYTES / 4 + 1),
                "Body"
            )
            .is_err()
        );
        assert!(
            EntryRevision::new(
                "entry-1",
                "rev-1",
                "Title",
                "🙂".repeat(MAX_ENTRY_CONTENT_BYTES / 4)
            )
            .is_ok()
        );
        assert!(
            EntryRevision::new(
                "entry-1",
                "rev-1",
                "t".repeat(MAX_ENTRY_TITLE_BYTES),
                "b".repeat(MAX_ENTRY_CONTENT_BYTES),
            )
            .is_ok()
        );
        assert!(
            EntryRevision::new(
                "entry-1",
                "rev-1",
                "Title",
                "b".repeat(MAX_ENTRY_CONTENT_BYTES + 1),
            )
            .is_err()
        );
    }

    #[test]
    fn integer_scoring_has_complete_sorted_term_evidence() {
        let snapshot = select(
            "rust rust durable",
            &[entry("entry-1", "Rust", "rust durable durable")],
        )
        .unwrap();
        let hit = &snapshot.hits()[0];
        assert_eq!(hit.score(), 24);
        assert_eq!(
            hit.matched_terms()
                .iter()
                .map(|term| (term.token(), term.contribution()))
                .collect::<Vec<_>>(),
            [("durable", 4), ("rust", 20)]
        );
        snapshot.validate().unwrap();
    }

    #[test]
    fn stable_ties_ignore_input_order() {
        let alpha = entry("alpha", "Guide", "shared term");
        let beta = entry("beta", "Guide", "shared term");
        let first = select("shared", &[beta.clone(), alpha.clone()]).unwrap();
        let second = select("shared", &[alpha, beta]).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first
                .hits()
                .iter()
                .map(|hit| hit.entry().entry_id())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn stable_ties_use_revision_after_entry_id() {
        let r2 = EntryRevision::new("same", "r2", "Guide", "shared").unwrap();
        let r1 = EntryRevision::new("same", "r1", "Guide", "shared").unwrap();
        let snapshot = select("shared", &[r2, r1]).unwrap();
        assert_eq!(snapshot.hits()[0].entry().revision(), "r1");
        assert_eq!(snapshot.hits()[1].entry().revision(), "r2");
    }

    #[test]
    fn selection_never_exceeds_six_hits_and_explains_the_rest() {
        let entries = (0..8)
            .map(|index| entry(&format!("entry-{index}"), "Match", "match"))
            .collect::<Vec<_>>();
        let snapshot = select("match", &entries).unwrap();
        assert_eq!(snapshot.hits().len(), MAX_SELECTION_HITS);
        assert_eq!(snapshot.evidence().candidates().len(), 8);
        assert!(
            snapshot.evidence().candidates()[..6]
                .iter()
                .all(|candidate| candidate.disposition() == CandidateDisposition::Included)
        );
        assert!(
            snapshot.evidence().candidates()[6..]
                .iter()
                .all(|candidate| candidate.disposition() == CandidateDisposition::HitLimit)
        );
    }

    #[test]
    fn oversized_ranked_entry_is_dropped_whole_and_next_entry_can_fit() {
        let large_content = format!(
            "needle {}",
            "x".repeat(MAX_ENTRY_CONTENT_BYTES - "needle ".len())
        );
        let first = entry("a-large", "Needle Needle Needle", &large_content);
        let dropped = entry("b-large", "Needle Needle", &large_content);
        let small = entry("c-small", "Needle", "needle remains complete");
        let snapshot = select("needle", &[first.clone(), dropped, small.clone()]).unwrap();
        assert_eq!(snapshot.hits().len(), 2);
        assert_eq!(snapshot.hits()[0].entry(), &first);
        assert_eq!(snapshot.hits()[1].entry(), &small);
        assert_eq!(
            snapshot.evidence().candidates()[0].disposition(),
            CandidateDisposition::Included
        );
        assert_eq!(
            snapshot.evidence().candidates()[1].disposition(),
            CandidateDisposition::ContextBudget
        );
        assert_eq!(
            snapshot.evidence().candidates()[2].disposition(),
            CandidateDisposition::Included
        );
        assert!(!snapshot.canonical_context().contains("b-large"));
        assert!(
            snapshot
                .canonical_context()
                .contains("needle remains complete")
        );
    }

    #[test]
    fn utf8_content_is_included_exactly_without_byte_slicing() {
        let content = format!("知识 {}", "🙂".repeat(2_000));
        let revision = entry("utf8", "知识", &content);
        let snapshot = select("知", &[revision]).unwrap();
        assert_eq!(snapshot.hits()[0].entry().content(), content);
        assert!(snapshot.context_bytes() as usize <= MAX_CANONICAL_CONTEXT_BYTES);
        assert!(snapshot.canonical_context().contains(&content));
    }

    #[test]
    fn canonical_renderer_has_fixed_field_order_and_escapes_content() {
        let snapshot = select(
            "quoted",
            &[entry("entry-1", "Quoted", "quoted \"line\"\nback\\slash")],
        )
        .unwrap();
        let expected_prefix = concat!(
            "{\"schema_version\":1,\"renderer\":",
            "\"zeus.canonical-knowledge-context.v1\",\"entries\":[",
            "{\"entry_id\":\"entry-1\",\"revision\":\"r1\",",
            "\"content_digest\":\""
        );
        assert!(snapshot.canonical_context().starts_with(expected_prefix));
        assert!(
            snapshot
                .canonical_context()
                .contains("\"content\":\"quoted \\\"line\\\"\\nback\\\\slash\"")
        );
        assert_eq!(
            render_canonical_context(snapshot.hits()).unwrap(),
            snapshot.canonical_context()
        );
    }

    #[test]
    fn empty_match_set_has_stable_nonempty_canonical_context() {
        let snapshot = select("absent", &[entry("entry-1", "Title", "Body")]).unwrap();
        assert!(snapshot.hits().is_empty());
        assert_eq!(
            snapshot.canonical_context(),
            concat!(
                "{\"schema_version\":1,\"renderer\":",
                "\"zeus.canonical-knowledge-context.v1\",\"entries\":[]}"
            )
        );
        assert_eq!(snapshot.evidence().matched_entry_revisions(), 0);
        assert_eq!(snapshot.evidence().unmatched_entry_revisions(), 1);
    }

    #[test]
    fn digests_are_exact_and_domain_separated() {
        let query = query_digest("same").unwrap();
        assert_eq!(
            query.to_hex(),
            "36298a2c512aab218df23b8af06852b6b0bc92915d3921a72f4f268cd031d232"
        );
        assert_eq!(
            content_digest("same").to_hex(),
            "386b9b194dfabe75c577d27e657cafac4264ba2735df5ea582929ddd1d6b99d3"
        );
        assert_eq!(
            canonical_context_digest("same").to_hex(),
            "bd60d3c04db216dbb3342c9f9105c22d7951ae8fc464c9e5deb277797372fa4c"
        );
        assert_eq!(query, query_digest("same").unwrap());
        assert_ne!(query, query_digest("Same").unwrap());
        assert_ne!(query, content_digest("same"));
        assert_ne!(content_digest("same"), canonical_context_digest("same"));
        let snapshot = select("same", &[entry("entry", "Same", "same")]).unwrap();
        assert_eq!(
            snapshot.corpus_digest().to_hex(),
            "9451260434304c1497636983fd82bf675ab163be5e483f29167837ed1a4c465d"
        );
        assert_eq!(
            snapshot.snapshot_digest().unwrap().to_hex(),
            "6c0ccc05915a5f22de7dff32340109749fe8397e4b5df50b88df13af171c7d4d"
        );
        assert!(snapshot.matches_query("same").unwrap());
        assert!(!snapshot.matches_query("Same").unwrap());
        assert_ne!(
            snapshot.snapshot_digest().unwrap(),
            snapshot.context_digest()
        );

        let six = (0..6)
            .map(|index| entry(&format!("entry-{index}"), "Same", "same"))
            .collect::<Vec<_>>();
        let mut seven = six.clone();
        seven.push(entry("entry-6", "Same", "same"));
        let six = select("same", &six).unwrap();
        let seven = select("same", &seven).unwrap();
        assert_eq!(six.canonical_context(), seven.canonical_context());
        assert_eq!(six.context_digest(), seven.context_digest());
        assert_ne!(
            six.snapshot_digest().unwrap(),
            seven.snapshot_digest().unwrap()
        );
    }

    #[test]
    fn strict_query_duplicate_count_and_aggregate_bounds_fail_closed() {
        assert!(matches!(
            select("---", &[]),
            Err(KnowledgeError::QueryHasNoTokens)
        ));
        assert!(matches!(
            select(&"q".repeat(MAX_QUERY_BYTES + 1), &[]),
            Err(KnowledgeError::InvalidField { field: "query", .. })
        ));
        let duplicate = entry("same", "Same", "same");
        assert!(matches!(
            select("same", &[duplicate.clone(), duplicate]),
            Err(KnowledgeError::DuplicateEntryRevision { .. })
        ));

        let too_many = (0..=MAX_ENTRY_REVISIONS)
            .map(|index| entry(&format!("entry-{index}"), "Title", "body"))
            .collect::<Vec<_>>();
        assert!(matches!(
            select("body", &too_many),
            Err(KnowledgeError::TooManyEntryRevisions { .. })
        ));

        let content = format!("body {}", "x".repeat(MAX_ENTRY_CONTENT_BYTES - 5));
        let aggregate = (0..65)
            .map(|index| entry(&format!("aggregate-{index}"), "Title", &content))
            .collect::<Vec<_>>();
        assert!(matches!(
            select("body", &aggregate),
            Err(KnowledgeError::AggregateEntriesTooLarge { .. })
        ));
    }

    #[test]
    fn unique_term_limits_are_exact_and_fail_closed() {
        let query_32 = (0..MAX_QUERY_UNIQUE_TERMS)
            .map(|index| format!("q{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(select(&query_32, &[]).is_ok());
        let query_33 = format!("{query_32} q{MAX_QUERY_UNIQUE_TERMS}");
        assert!(matches!(
            select(&query_33, &[]),
            Err(KnowledgeError::TooManyQueryTerms { .. })
        ));

        let terms_256 = (0..MAX_ENTRY_UNIQUE_TERMS)
            .map(|index| format!("t{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(select("t0", &[entry("entry-256", "t0", &terms_256)],).is_ok());
        let terms_257 = format!("{terms_256} t{MAX_ENTRY_UNIQUE_TERMS}");
        assert!(matches!(
            select("t0", &[entry("entry-257", "t0", &terms_257)]),
            Err(KnowledgeError::TooManyEntryTerms { .. })
        ));
    }

    #[test]
    fn canonical_snapshot_payload_round_trips_and_rejects_noncanonical_input() {
        let snapshot = select(
            "durable knowledge",
            &[entry("entry", "Durable", "durable knowledge")],
        )
        .unwrap();
        let encoded = snapshot.canonical_payload_json().unwrap();
        assert_eq!(
            SelectionSnapshot::from_canonical_payload_json(&encoded).unwrap(),
            snapshot
        );

        let padded = format!(" {encoded}");
        assert!(matches!(
            SelectionSnapshot::from_canonical_payload_json(&padded),
            Err(KnowledgeError::NonCanonicalEnvelope)
        ));

        let mut unknown: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(matches!(
            SelectionSnapshot::from_canonical_payload_json(
                &serde_json::to_string(&unknown).unwrap()
            ),
            Err(KnowledgeError::Serialization(_))
        ));

        let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        tampered["canonical_context"] = serde_json::Value::String("{}".into());
        assert!(matches!(
            SelectionSnapshot::from_canonical_payload_json(
                &serde_json::to_string(&tampered).unwrap()
            ),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn digest_bearing_envelope_round_trips_and_rejects_tampering() {
        let entries = [entry("entry", "Durable", "durable knowledge")];
        let snapshot = select("durable knowledge", &entries).unwrap();
        let envelope = SelectionSnapshotEnvelope::new(snapshot.clone()).unwrap();
        assert_eq!(envelope.digest(), snapshot.snapshot_digest().unwrap());
        envelope
            .validate_for_selection("durable knowledge", &entries)
            .unwrap();

        let encoded = envelope.canonical_json().unwrap();
        let mut encoded_digest = Sha256::new();
        encoded_digest.update(encoded.as_bytes());
        assert_eq!(
            Sha256Digest(encoded_digest.finalize().into()).to_hex(),
            "bdc93bbd87c3b84db41643bf48b9364163976e74cfdfd289628cc6b1cd342806"
        );
        assert_eq!(
            SelectionSnapshotEnvelope::from_canonical_json(&encoded).unwrap(),
            envelope
        );

        let padded = format!(" {encoded}");
        assert!(matches!(
            SelectionSnapshotEnvelope::from_canonical_json(&padded),
            Err(KnowledgeError::NonCanonicalEnvelope)
        ));

        let mut unknown: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(matches!(
            SelectionSnapshotEnvelope::from_canonical_json(
                &serde_json::to_string(&unknown).unwrap()
            ),
            Err(KnowledgeError::Serialization(_))
        ));

        let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        tampered["digest"] = serde_json::Value::String("0".repeat(64));
        assert!(matches!(
            SelectionSnapshotEnvelope::from_canonical_json(
                &serde_json::to_string(&tampered).unwrap()
            ),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn corpus_revision_envelope_is_sorted_canonical_and_tamper_evident() {
        let alpha = entry("alpha", "Alpha", "alpha body");
        let beta = entry("beta", "Beta", "beta body");
        let envelope = CorpusRevisionEnvelope::new(vec![beta, alpha]).unwrap();
        assert_eq!(
            envelope
                .entries()
                .iter()
                .map(EntryRevision::entry_id)
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(
            envelope.digest(),
            corpus_digest(envelope.entries()).unwrap()
        );

        let encoded = envelope.canonical_json().unwrap();
        let mut encoded_digest = Sha256::new();
        encoded_digest.update(encoded.as_bytes());
        assert_eq!(
            Sha256Digest(encoded_digest.finalize().into()).to_hex(),
            "c0cacc10f8b700a78ede41ba23a10d4d3e2a2de199a5dac0d5091de8946e3e9e"
        );
        assert_eq!(
            CorpusRevisionEnvelope::from_canonical_json(&encoded).unwrap(),
            envelope
        );

        let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        tampered["entries"][0]["content"] = serde_json::Value::String("changed".into());
        assert!(matches!(
            CorpusRevisionEnvelope::from_canonical_json(&serde_json::to_string(&tampered).unwrap()),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));

        let mut reordered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        reordered["entries"].as_array_mut().unwrap().swap(0, 1);
        assert!(matches!(
            CorpusRevisionEnvelope::from_canonical_json(
                &serde_json::to_string(&reordered).unwrap()
            ),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));

        let mut unknown: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(matches!(
            CorpusRevisionEnvelope::from_canonical_json(&serde_json::to_string(&unknown).unwrap()),
            Err(KnowledgeError::Serialization(_))
        ));
    }

    #[test]
    fn corpus_digest_binds_every_revision_even_when_it_does_not_match() {
        let included = entry("included", "Match", "match");
        let unmatched_a = entry("unmatched-a", "Alpha", "alpha");
        let unmatched_b = entry("unmatched-b", "Beta", "beta");

        let first_entries = [included.clone(), unmatched_a];
        let reordered_entries = [first_entries[1].clone(), included.clone()];
        let changed_entries = [included, unmatched_b];
        let snapshot = select("match", &first_entries).unwrap();

        assert_eq!(
            snapshot.corpus_digest(),
            corpus_digest(&reordered_entries).unwrap()
        );
        snapshot
            .validate_for_selection("match", &reordered_entries)
            .unwrap();
        assert_ne!(
            snapshot.corpus_digest(),
            corpus_digest(&changed_entries).unwrap()
        );
        assert!(matches!(
            snapshot.validate_for_selection("match", &changed_entries),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn canonical_decoders_enforce_the_snapshot_byte_boundary_before_parsing() {
        let exact = " ".repeat(MAX_SELECTION_SNAPSHOT_BYTES);
        assert!(matches!(
            SelectionSnapshot::from_canonical_payload_json(&exact),
            Err(KnowledgeError::Serialization(_))
        ));
        assert!(matches!(
            SelectionSnapshotEnvelope::from_canonical_json(&exact),
            Err(KnowledgeError::Serialization(_))
        ));

        let oversized = " ".repeat(MAX_SELECTION_SNAPSHOT_BYTES + 1);
        assert!(matches!(
            SelectionSnapshot::from_canonical_payload_json(&oversized),
            Err(KnowledgeError::SelectionSnapshotTooLarge {
                max_bytes: MAX_SELECTION_SNAPSHOT_BYTES,
                actual_bytes,
            }) if actual_bytes == MAX_SELECTION_SNAPSHOT_BYTES + 1
        ));
        assert!(matches!(
            SelectionSnapshotEnvelope::from_canonical_json(&oversized),
            Err(KnowledgeError::SelectionSnapshotTooLarge {
                max_bytes: MAX_SELECTION_SNAPSHOT_BYTES,
                actual_bytes,
            }) if actual_bytes == MAX_SELECTION_SNAPSHOT_BYTES + 1
        ));
    }

    #[test]
    fn canonical_corpus_decoder_enforces_its_byte_boundary_before_parsing() {
        let exact = " ".repeat(MAX_CORPUS_REVISION_ENVELOPE_BYTES);
        assert!(matches!(
            CorpusRevisionEnvelope::from_canonical_json(&exact),
            Err(KnowledgeError::Serialization(_))
        ));

        let oversized = " ".repeat(MAX_CORPUS_REVISION_ENVELOPE_BYTES + 1);
        assert!(matches!(
            CorpusRevisionEnvelope::from_canonical_json(&oversized),
            Err(KnowledgeError::CorpusRevisionEnvelopeTooLarge {
                max_bytes: MAX_CORPUS_REVISION_ENVELOPE_BYTES,
                actual_bytes,
            }) if actual_bytes == MAX_CORPUS_REVISION_ENVELOPE_BYTES + 1
        ));
    }

    #[test]
    fn snapshot_validation_detects_context_and_evidence_tampering() {
        let mut snapshot = select("match", &[entry("entry", "Match", "match")]).unwrap();
        snapshot.canonical_context.push(' ');
        assert!(matches!(
            snapshot.validate(),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));

        let mut snapshot = select("match", &[entry("entry", "Match", "match")]).unwrap();
        snapshot.evidence.candidates[0].score += 1;
        assert!(matches!(
            snapshot.validate(),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn query_bound_validation_recomputes_the_complete_term_evidence() {
        let mut snapshot =
            select("durable rust", &[entry("entry", "Rust", "durable rust")]).unwrap();
        snapshot.hits[0].matched_terms.remove(0);
        let retained_score = snapshot.hits[0].matched_terms[0].contribution;
        snapshot.hits[0].score = retained_score;
        snapshot.evidence.candidates[0].score = retained_score;

        snapshot.validate().unwrap();
        assert!(matches!(
            snapshot.validate_for_query("durable rust"),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn corpus_bound_validation_detects_a_coherent_included_to_omitted_rewrite() {
        let entries = [entry("entry", "Match", "match")];
        let mut snapshot = select("match", &entries).unwrap();
        snapshot.hits.clear();
        snapshot.evidence.candidates[0].disposition = CandidateDisposition::ContextBudget;
        snapshot.canonical_context = render_context_unbounded(&[]);
        snapshot.context_bytes = snapshot.canonical_context.len() as u32;
        snapshot.context_digest = canonical_context_digest(&snapshot.canonical_context);

        snapshot.validate().unwrap();
        snapshot.validate_for_query("match").unwrap();
        let encoded = snapshot.canonical_payload_json().unwrap();
        SelectionSnapshot::from_canonical_payload_json(&encoded).unwrap();
        assert!(matches!(
            snapshot.validate_for_selection("match", &entries),
            Err(KnowledgeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn context_budget_boundary_is_exact_in_utf8_bytes() {
        let first_content = format!(
            "needle {}",
            "x".repeat(MAX_ENTRY_CONTENT_BYTES - "needle ".len())
        );
        let first = entry("a-boundary", "Needle Needle Needle", &first_content);
        let mut low = 1_usize;
        let mut high = MAX_ENTRY_CONTENT_BYTES - "needle ".len();
        while low < high {
            let middle = (low + high).div_ceil(2);
            let content = format!("needle {}", "x".repeat(middle));
            let second = entry("b-boundary", "Needle Needle", &content);
            let snapshot = select("needle", &[first.clone(), second]).unwrap();
            if snapshot.hits().len() == 1 {
                high = middle - 1;
            } else {
                low = middle;
            }
        }

        let fitting_content = format!("needle {}", "x".repeat(low));
        let fitting = select(
            "needle",
            &[
                first.clone(),
                entry("b-boundary", "Needle Needle", &fitting_content),
            ],
        )
        .unwrap();
        assert_eq!(
            fitting.context_bytes() as usize,
            MAX_CANONICAL_CONTEXT_BYTES
        );
        assert_eq!(fitting.hits()[1].entry().content(), fitting_content);

        let oversized_content = format!("needle {}", "x".repeat(low + 1));
        let oversized = select(
            "needle",
            &[
                first,
                entry("b-boundary", "Needle Needle", &oversized_content),
            ],
        )
        .unwrap();
        assert_eq!(oversized.hits().len(), 1);
        assert_eq!(
            oversized.evidence().candidates()[1].disposition(),
            CandidateDisposition::ContextBudget
        );
    }
}
