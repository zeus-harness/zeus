use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ToolCall, ToolResult};

/// Ordered pure-domain stages of a Capability invocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPipelinePhase {
    Validate,
    TenantPolicy,
    CapabilityPolicy,
    Approval,
    PersistCall,
    Execute,
    NormalizeAndRedact,
    PersistResult,
    Audit,
}

impl ToolPipelinePhase {
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Validate => Some(Self::TenantPolicy),
            Self::TenantPolicy => Some(Self::CapabilityPolicy),
            Self::CapabilityPolicy => Some(Self::Approval),
            Self::Approval => Some(Self::PersistCall),
            Self::PersistCall => Some(Self::Execute),
            Self::Execute => Some(Self::NormalizeAndRedact),
            Self::NormalizeAndRedact => Some(Self::PersistResult),
            Self::PersistResult => Some(Self::Audit),
            Self::Audit => None,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Audit)
    }
}

/// Pure state for one tool call moving through the fixed pipeline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolPipeline {
    call: ToolCall,
    phase: ToolPipelinePhase,
    result: Option<ToolResult>,
}

impl ToolPipeline {
    #[must_use]
    pub const fn new(call: ToolCall) -> Self {
        Self {
            call,
            phase: ToolPipelinePhase::Validate,
            result: None,
        }
    }

    /// Advances exactly one fixed pipeline phase.
    ///
    /// # Errors
    ///
    /// Returns an error when the pipeline is complete or when result
    /// persistence is skipped.
    pub fn advance(&mut self) -> Result<ToolPipelinePhase, ToolPipelineError> {
        if self.phase == ToolPipelinePhase::PersistResult && self.result.is_none() {
            return Err(ToolPipelineError::ResultRequired);
        }

        let next = self
            .phase
            .next()
            .ok_or(ToolPipelineError::AlreadyComplete)?;
        self.phase = next;
        Ok(next)
    }

    /// Records the normalized result at the persistence stage.
    ///
    /// # Errors
    ///
    /// Returns [`ToolPipelineError`] when the pipeline is not at result
    /// persistence, the result belongs to another call, or a result was
    /// already recorded.
    pub fn record_result(&mut self, result: ToolResult) -> Result<(), ToolPipelineError> {
        if self.phase != ToolPipelinePhase::PersistResult {
            return Err(ToolPipelineError::WrongPhase {
                expected: ToolPipelinePhase::PersistResult,
                actual: self.phase,
            });
        }
        if result.call_id != self.call.call_id {
            return Err(ToolPipelineError::CallIdMismatch {
                expected: self.call.call_id.clone(),
                actual: result.call_id,
            });
        }
        if self.result.is_some() {
            return Err(ToolPipelineError::ResultAlreadyRecorded);
        }
        self.result = Some(result);
        Ok(())
    }

    /// Closes an in-flight call with a deterministic synthetic cancellation
    /// result. The result still has to pass through `PersistResult` and
    /// `Audit` like a normal result.
    ///
    /// # Errors
    ///
    /// Returns [`ToolPipelineError::AlreadyComplete`] after audit or
    /// [`ToolPipelineError::ResultAlreadyRecorded`] when the call is already
    /// closed.
    pub fn cancel(&mut self) -> Result<ToolResult, ToolPipelineError> {
        if self.phase == ToolPipelinePhase::Audit {
            return Err(ToolPipelineError::AlreadyComplete);
        }
        if self.result.is_some() {
            return Err(ToolPipelineError::ResultAlreadyRecorded);
        }

        let result = ToolResult::canceled(self.call.call_id.clone());
        self.result = Some(result.clone());
        self.phase = ToolPipelinePhase::PersistResult;
        Ok(result)
    }

    #[must_use]
    pub const fn call(&self) -> &ToolCall {
        &self.call
    }

    #[must_use]
    pub const fn phase(&self) -> ToolPipelinePhase {
        self.phase
    }

    #[must_use]
    pub const fn result(&self) -> Option<&ToolResult> {
        self.result.as_ref()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ToolPipelineError {
    #[error("tool pipeline is already complete")]
    AlreadyComplete,
    #[error("persist_result requires a tool result")]
    ResultRequired,
    #[error("tool result can only be recorded in {expected:?}, current phase is {actual:?}")]
    WrongPhase {
        expected: ToolPipelinePhase,
        actual: ToolPipelinePhase,
    },
    #[error("tool result call ID does not match the tool call")]
    CallIdMismatch { expected: String, actual: String },
    #[error("tool result has already been recorded")]
    ResultAlreadyRecorded,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ToolPipeline, ToolPipelineError, ToolPipelinePhase};
    use crate::{ToolCall, ToolResult};

    #[test]
    fn pipeline_requires_result_before_audit() {
        let mut pipeline =
            ToolPipeline::new(ToolCall::new("call-1", "crm.read", json!({ "id": 1 })));

        for expected in [
            ToolPipelinePhase::TenantPolicy,
            ToolPipelinePhase::CapabilityPolicy,
            ToolPipelinePhase::Approval,
            ToolPipelinePhase::PersistCall,
            ToolPipelinePhase::Execute,
            ToolPipelinePhase::NormalizeAndRedact,
            ToolPipelinePhase::PersistResult,
        ] {
            assert_eq!(pipeline.advance(), Ok(expected));
        }
        assert_eq!(pipeline.advance(), Err(ToolPipelineError::ResultRequired));

        pipeline
            .record_result(ToolResult::new("call-1", json!({ "ok": true })))
            .expect("result is recorded at the persistence stage");
        assert_eq!(pipeline.advance(), Ok(ToolPipelinePhase::Audit));
        assert!(pipeline.phase().is_terminal());
    }

    #[test]
    fn cancellation_produces_a_persistable_synthetic_result() {
        let mut pipeline = ToolPipeline::new(ToolCall::new("call-1", "crm.write", json!({})));

        let result = pipeline.cancel().expect("in-flight calls can be canceled");

        assert!(result.synthetic);
        assert_eq!(pipeline.phase(), ToolPipelinePhase::PersistResult);
        assert_eq!(pipeline.result(), Some(&result));
    }
}
