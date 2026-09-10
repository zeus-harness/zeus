use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    WaitingApproval,
    WaitingChild,
    Succeeded,
    Failed,
    Canceled,
}

impl RunState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Canceled)
    }

    /// Applies one legal state transition.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the transition is not legal from the
    /// current state.
    pub fn transition(self, transition: RunTransition) -> Result<Self, TransitionError> {
        use RunState::{
            Canceled, Failed, Queued, Running, Succeeded, WaitingApproval, WaitingChild,
        };
        use RunTransition::{
            Cancel, Claim, Complete, Fail, ReleaseForRetry, Resume, WaitForApproval, WaitForChild,
        };

        let target = match (self, transition) {
            (Queued, Claim) => Running,
            (Queued | Running | WaitingApproval | WaitingChild, Cancel) => Canceled,
            (Running, WaitForApproval) => WaitingApproval,
            (Running, WaitForChild) => WaitingChild,
            (Running, Complete) => Succeeded,
            (Running, Fail) => Failed,
            (Running, ReleaseForRetry) | (WaitingApproval | WaitingChild, Resume) => Queued,
            _ => {
                return Err(TransitionError {
                    state: self,
                    transition,
                });
            }
        };

        Ok(target)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTransition {
    Claim,
    WaitForApproval,
    WaitForChild,
    Complete,
    Fail,
    Cancel,
    ReleaseForRetry,
    Resume,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunLimits {
    pub max_steps: u16,
    pub max_runtime_seconds: u32,
    pub token_budget: Option<u64>,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            max_steps: 32,
            max_runtime_seconds: 900,
            token_budget: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("cannot apply {transition:?} while run is {state:?}")]
pub struct TransitionError {
    pub state: RunState,
    pub transition: RunTransition,
}

#[cfg(test)]
mod tests {
    use super::{RunState, RunTransition};

    #[test]
    fn accepted_run_path_reaches_success() {
        let running = RunState::Queued
            .transition(RunTransition::Claim)
            .expect("queued run can be claimed");
        let succeeded = running
            .transition(RunTransition::Complete)
            .expect("running run can complete");
        assert_eq!(succeeded, RunState::Succeeded);
        assert!(succeeded.is_terminal());
    }

    #[test]
    fn approval_releases_the_lease_before_resume() {
        let waiting = RunState::Running
            .transition(RunTransition::WaitForApproval)
            .expect("running run can wait");
        assert_eq!(
            waiting.transition(RunTransition::Resume),
            Ok(RunState::Queued)
        );
    }

    #[test]
    fn terminal_runs_reject_more_transitions() {
        assert!(
            RunState::Succeeded
                .transition(RunTransition::Claim)
                .is_err()
        );
    }
}
