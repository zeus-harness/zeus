use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

id_type!(OrganizationId);
id_type!(WorkspaceId);
id_type!(WorkItemId);
id_type!(SessionId);
id_type!(RunId);
id_type!(AgentVersionId);
id_type!(WorkflowVersionId);
id_type!(CapabilityId);
id_type!(EventId);

#[cfg(test)]
mod tests {
    use super::RunId;

    #[test]
    fn generated_ids_are_uuid_v7() {
        assert_eq!(RunId::new().into_uuid().get_version_num(), 7);
    }

    #[test]
    fn ids_round_trip_as_strings() {
        let id = RunId::new();
        let parsed = id.to_string().parse::<RunId>().expect("valid UUID");
        assert_eq!(id, parsed);
    }
}
