use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkItemState {
    Open,
    InProgress,
    Blocked,
    Completed,
    Canceled,
}

impl WorkItemState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Canceled => "canceled",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Canceled)
    }

    /// Checks whether one persisted state can move to another.
    ///
    /// # Errors
    ///
    /// Returns [`WorkItemTransitionError`] for a transition that would reopen a
    /// terminal item or skip the accepted collaboration states.
    pub fn transition(self, target: Self) -> Result<Self, WorkItemTransitionError> {
        if self == target {
            return Ok(self);
        }
        let allowed = matches!(
            (self, target),
            (
                Self::Open,
                Self::InProgress | Self::Blocked | Self::Completed | Self::Canceled
            ) | (
                Self::InProgress,
                Self::Open | Self::Blocked | Self::Completed | Self::Canceled
            ) | (
                Self::Blocked,
                Self::Open | Self::InProgress | Self::Canceled
            )
        );
        if allowed {
            Ok(target)
        } else {
            Err(WorkItemTransitionError {
                current: self,
                target,
            })
        }
    }
}

impl TryFrom<&str> for WorkItemState {
    type Error = WorkItemStateParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "open" => Ok(Self::Open),
            "in_progress" => Ok(Self::InProgress),
            "blocked" => Ok(Self::Blocked),
            "completed" => Ok(Self::Completed),
            "canceled" => Ok(Self::Canceled),
            _ => Err(WorkItemStateParseError),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("unknown work item state")]
pub struct WorkItemStateParseError;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("cannot move work item from {current:?} to {target:?}")]
pub struct WorkItemTransitionError {
    pub current: WorkItemState,
    pub target: WorkItemState,
}

#[cfg(test)]
mod tests {
    use super::WorkItemState;

    #[test]
    fn active_work_can_move_through_collaboration_states() {
        assert_eq!(
            WorkItemState::Open.transition(WorkItemState::Blocked),
            Ok(WorkItemState::Blocked)
        );
        assert_eq!(
            WorkItemState::Blocked.transition(WorkItemState::InProgress),
            Ok(WorkItemState::InProgress)
        );
        assert_eq!(
            WorkItemState::InProgress.transition(WorkItemState::Completed),
            Ok(WorkItemState::Completed)
        );
    }

    #[test]
    fn terminal_work_cannot_be_reopened() {
        assert!(
            WorkItemState::Completed
                .transition(WorkItemState::InProgress)
                .is_err()
        );
        assert!(
            WorkItemState::Canceled
                .transition(WorkItemState::Open)
                .is_err()
        );
    }
}
