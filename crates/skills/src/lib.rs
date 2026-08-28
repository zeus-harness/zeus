//! Immutable, versioned Agent skills loaded before the runtime starts.
//!
//! Skill bodies are exposed only through ordinary read-only tools. This keeps
//! model-visible content on Zeus' durable tool-result path while binding the
//! exact startup catalog digest into every Agent deployment manifest.

use std::{collections::BTreeMap, sync::Arc};

use protocol::{SandboxProfile, ToolEffect};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tools::{
    ExecutionFuture, ExecutionRequest, ExecutorError, ObjectSchema, ParameterSpec, RegistryError,
    ToolDescriptor, ToolExecutor, ToolOutput, ToolRegistry,
};

pub const SKILL_CATALOG_FORMAT_VERSION: u32 = 1;
pub const SKILL_CATALOG_FILE_MAX_BYTES: usize = 512 * 1024;
pub const SKILL_CATALOG_MAX_SKILLS: usize = 64;
pub const SKILL_NAME_MAX_BYTES: usize = 64;
pub const SKILL_VERSION_MAX_BYTES: usize = 64;
pub const SKILL_DESCRIPTION_MAX_BYTES: usize = 256;
pub const SKILL_CONTENT_MAX_BYTES: usize = 24 * 1024;
pub const SKILL_LIST_TOOL_NAME: &str = "skill_list";
pub const SKILL_LOAD_TOOL_NAME: &str = "skill_load";

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SkillCatalogError {
    #[error("skill catalog must be no larger than {SKILL_CATALOG_FILE_MAX_BYTES} bytes")]
    FileTooLarge,
    #[error("skill catalog is not valid strict JSON: {0}")]
    InvalidJson(String),
    #[error("skill catalog version must be {SKILL_CATALOG_FORMAT_VERSION}")]
    UnsupportedVersion,
    #[error("skill catalog must contain between 1 and {SKILL_CATALOG_MAX_SKILLS} skills")]
    InvalidCapacity,
    #[error(
        "skill name must start with a lowercase ASCII letter and contain at most {SKILL_NAME_MAX_BYTES} lowercase ASCII letters, digits, underscores, or hyphens"
    )]
    InvalidName,
    #[error("invalid skill `{name}`: {detail}")]
    InvalidSkill { name: String, detail: String },
    #[error("duplicate skill name `{0}`")]
    DuplicateName(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillCatalogDocument {
    version: u32,
    skills: Vec<SkillDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillDocument {
    name: String,
    version: String,
    description: String,
    content: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SkillDefinition {
    name: String,
    version: String,
    description: String,
    content: String,
    digest: String,
}

impl SkillDefinition {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillCatalog {
    skills: BTreeMap<String, SkillDefinition>,
    digest: String,
}

impl SkillCatalog {
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, SkillCatalogError> {
        if bytes.len() > SKILL_CATALOG_FILE_MAX_BYTES {
            return Err(SkillCatalogError::FileTooLarge);
        }
        let document: SkillCatalogDocument = serde_json::from_slice(bytes)
            .map_err(|error| SkillCatalogError::InvalidJson(error.to_string()))?;
        Self::from_document(document)
    }

    fn from_document(document: SkillCatalogDocument) -> Result<Self, SkillCatalogError> {
        if document.version != SKILL_CATALOG_FORMAT_VERSION {
            return Err(SkillCatalogError::UnsupportedVersion);
        }
        if document.skills.is_empty() || document.skills.len() > SKILL_CATALOG_MAX_SKILLS {
            return Err(SkillCatalogError::InvalidCapacity);
        }

        let mut skills = BTreeMap::new();
        for document in document.skills {
            validate_skill(&document)?;
            let digest = skill_digest(&document);
            let definition = SkillDefinition {
                name: document.name.clone(),
                version: document.version,
                description: document.description,
                content: document.content,
                digest,
            };
            if skills.insert(document.name.clone(), definition).is_some() {
                return Err(SkillCatalogError::DuplicateName(document.name));
            }
        }

        let digest = catalog_digest(&skills);
        Ok(Self { skills, digest })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&SkillDefinition> {
        self.skills.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SkillDefinition> {
        self.skills.values()
    }
}

fn validate_skill(skill: &SkillDocument) -> Result<(), SkillCatalogError> {
    if !valid_skill_name(&skill.name) {
        return Err(SkillCatalogError::InvalidName);
    }
    if skill.version.is_empty()
        || skill.version.len() > SKILL_VERSION_MAX_BYTES
        || !skill
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid_skill(
            &skill.name,
            format!(
                "version must contain 1..={SKILL_VERSION_MAX_BYTES} ASCII letters, digits, dots, underscores, or hyphens"
            ),
        ));
    }
    if skill.description.is_empty()
        || skill.description.len() > SKILL_DESCRIPTION_MAX_BYTES
        || skill.description.trim() != skill.description
        || skill.description.chars().any(char::is_control)
    {
        return Err(invalid_skill(
            &skill.name,
            format!(
                "description must be canonical, control-free, and contain 1..={SKILL_DESCRIPTION_MAX_BYTES} UTF-8 bytes"
            ),
        ));
    }
    if skill.content.trim().is_empty()
        || skill.content.len() > SKILL_CONTENT_MAX_BYTES
        || skill
            .content
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(invalid_skill(
            &skill.name,
            format!(
                "content must be non-blank, contain at most {SKILL_CONTENT_MAX_BYTES} UTF-8 bytes, and use only newline or tab control characters"
            ),
        ));
    }
    Ok(())
}

fn invalid_skill(name: &str, detail: String) -> SkillCatalogError {
    SkillCatalogError::InvalidSkill {
        name: name.to_owned(),
        detail,
    }
}

fn valid_skill_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= SKILL_NAME_MAX_BYTES
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn skill_digest(skill: &SkillDocument) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zeus-skill-v1\0");
    hash_field(&mut hasher, skill.name.as_bytes());
    hash_field(&mut hasher, skill.version.as_bytes());
    hash_field(&mut hasher, skill.description.as_bytes());
    hash_field(&mut hasher, skill.content.as_bytes());
    hex_digest(hasher.finalize())
}

fn catalog_digest(skills: &BTreeMap<String, SkillDefinition>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zeus-skill-catalog-v1\0");
    hasher.update((skills.len() as u64).to_be_bytes());
    for skill in skills.values() {
        hash_field(&mut hasher, skill.name.as_bytes());
        hash_field(&mut hasher, skill.digest.as_bytes());
    }
    hex_digest(hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn skill_tool_descriptors(catalog: &SkillCatalog) -> [ToolDescriptor; 2] {
    [
        ToolDescriptor {
            name: SKILL_LIST_TOOL_NAME.into(),
            version: catalog.digest.clone(),
            description:
                "List the immutable versioned skills available to this Agent deployment".into(),
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            input_schema: ObjectSchema::empty(),
        },
        ToolDescriptor {
            name: SKILL_LOAD_TOOL_NAME.into(),
            version: catalog.digest.clone(),
            description:
                "Load one exact skill body from the immutable catalog bound to this Agent deployment"
                    .into(),
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            input_schema: ObjectSchema {
                max_serialized_bytes: 96,
                properties: BTreeMap::from([(
                    "name".into(),
                    ParameterSpec::required_string(SKILL_NAME_MAX_BYTES),
                )]),
            },
        },
    ]
}

pub fn register_skill_tools(
    registry: &mut ToolRegistry,
    catalog: Arc<SkillCatalog>,
) -> Result<(), RegistryError> {
    let [list, load] = skill_tool_descriptors(&catalog);
    registry.register(list, SkillListExecutor(Arc::clone(&catalog)))?;
    registry.register(load, SkillLoadExecutor(catalog))?;
    Ok(())
}

#[derive(Clone)]
struct SkillListExecutor(Arc<SkillCatalog>);

impl ToolExecutor for SkillListExecutor {
    fn execute(&self, _request: ExecutionRequest) -> ExecutionFuture<'_> {
        let catalog = Arc::clone(&self.0);
        Box::pin(async move {
            let skills = catalog
                .iter()
                .map(|skill| {
                    serde_json::json!({
                        "name": skill.name,
                        "version": skill.version,
                        "description": skill.description,
                        "digest": skill.digest,
                    })
                })
                .collect::<Vec<_>>();
            Ok(ToolOutput {
                value: serde_json::json!({
                    "catalog_digest": catalog.digest,
                    "skills": skills,
                }),
                replayed: false,
                provider_request_id: None,
            })
        })
    }
}

#[derive(Clone)]
struct SkillLoadExecutor(Arc<SkillCatalog>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillLoadArguments {
    name: String,
}

impl ToolExecutor for SkillLoadExecutor {
    fn execute(&self, request: ExecutionRequest) -> ExecutionFuture<'_> {
        let catalog = Arc::clone(&self.0);
        Box::pin(async move {
            let arguments: SkillLoadArguments = serde_json::from_value(request.call.arguments)
                .map_err(|_| ExecutorError::Failed {
                    code: "invalid_arguments".into(),
                    message: "Skill load arguments are invalid".into(),
                    retryable: false,
                })?;
            let skill = catalog
                .get(&arguments.name)
                .ok_or_else(|| ExecutorError::Failed {
                    code: "skill_not_found".into(),
                    message: "The requested skill is not present in the deployment-bound catalog"
                        .into(),
                    retryable: false,
                })?;
            Ok(ToolOutput {
                value: serde_json::json!({
                    "catalog_digest": catalog.digest,
                    "name": skill.name,
                    "version": skill.version,
                    "description": skill.description,
                    "content": skill.content,
                    "digest": skill.digest,
                }),
                replayed: false,
                provider_request_id: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{ToolCall, ToolExecutorStatus};
    use tools::arguments_digest;

    fn catalog(bytes: &[u8]) -> SkillCatalog {
        SkillCatalog::from_json_slice(bytes).unwrap()
    }

    fn sample(first: &str, second: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "skills": [
                {"name": first, "version": "1.0.0", "description": format!("{first} skill"), "content": format!("# {first}\nDo {first}.")},
                {"name": second, "version": "1.0.0", "description": format!("{second} skill"), "content": format!("# {second}\nDo {second}.")}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn catalog_is_strict_bounded_sorted_and_digest_stable() {
        let first = catalog(&sample("zeta", "alpha"));
        let second = catalog(&sample("alpha", "zeta"));
        assert_eq!(first.digest(), second.digest());
        assert_eq!(
            first.iter().map(SkillDefinition::name).collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );
        assert_eq!(first.digest().len(), 64);
        assert_eq!(
            first.digest(),
            "f4bd1054731e504e3599472c3d31eff121ea7e64408e286de7e71e079a79a5a7"
        );

        assert!(
            SkillCatalog::from_json_slice(br#"{"version":1,"skills":[],"extra":true}"#).is_err()
        );
        assert!(
            SkillCatalog::from_json_slice(&vec![b' '; SKILL_CATALOG_FILE_MAX_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn catalog_rejects_ambiguous_or_unsafe_definitions() {
        for value in [
            serde_json::json!({"version": 2, "skills": [{"name":"alpha","version":"1","description":"Alpha","content":"body"}]}),
            serde_json::json!({"version": 1, "skills": [{"name":"Alpha","version":"1","description":"Alpha","content":"body"}]}),
            serde_json::json!({"version": 1, "skills": [{"name":"alpha","version":"1","description":" Alpha","content":"body"}]}),
            serde_json::json!({"version": 1, "skills": [{"name":"alpha","version":"1","description":"Alpha","content":"body\r\n"}]}),
            serde_json::json!({"version": 1, "skills": [{"name":"alpha","version":"1","description":"Alpha","content":" \n\t"}]}),
            serde_json::json!({"version": 1, "skills": [{"name":"alpha","version":"1","description":"Alpha","content":"body"},{"name":"alpha","version":"2","description":"Again","content":"other"}]}),
        ] {
            assert!(SkillCatalog::from_json_slice(&serde_json::to_vec(&value).unwrap()).is_err());
        }

        let unsafe_name = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "skills": [{
                "name": "bad\nforged-log-entry",
                "version": "1",
                "description": "Alpha",
                "content": "body"
            }]
        }))
        .unwrap();
        let diagnostic = SkillCatalog::from_json_slice(&unsafe_name)
            .unwrap_err()
            .to_string();
        assert!(!diagnostic.contains("forged-log-entry"));
    }

    #[test]
    fn catalog_digest_tracks_every_model_visible_skill_field() {
        let baseline = catalog(br#"{"version":1,"skills":[{"name":"alpha","version":"1","description":"Alpha","content":"body"}]}"#);
        for changed in [
            br#"{"version":1,"skills":[{"name":"beta","version":"1","description":"Alpha","content":"body"}]}"#.as_slice(),
            br#"{"version":1,"skills":[{"name":"alpha","version":"2","description":"Alpha","content":"body"}]}"#.as_slice(),
            br#"{"version":1,"skills":[{"name":"alpha","version":"1","description":"Changed","content":"body"}]}"#.as_slice(),
            br#"{"version":1,"skills":[{"name":"alpha","version":"1","description":"Alpha","content":"changed"}]}"#.as_slice(),
        ] {
            assert_ne!(baseline.digest(), catalog(changed).digest());
        }
    }

    fn call(descriptor: &ToolDescriptor, arguments: serde_json::Value) -> ToolCall {
        ToolCall {
            call_id: "call-skill-test".into(),
            tool: descriptor.name.clone(),
            tool_version: descriptor.version.clone(),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            effect: descriptor.effect.clone(),
            sandbox_profile: descriptor.sandbox_profile.clone(),
            executor_status: ToolExecutorStatus::Available,
        }
    }

    #[tokio::test]
    async fn tools_list_and_load_exact_immutable_catalog_content() {
        let startup_catalog = Arc::new(catalog(&sample("zeta", "alpha")));
        let mut registry = ToolRegistry::new();
        register_skill_tools(&mut registry, Arc::clone(&startup_catalog)).unwrap();

        let list = registry.descriptor(SKILL_LIST_TOOL_NAME).unwrap().clone();
        assert_eq!(list.version, startup_catalog.digest());
        let output = registry
            .dispatch(call(&list, serde_json::json!({})), "production")
            .await
            .unwrap();
        assert_eq!(output.value["skills"][0]["name"], "alpha");
        assert_eq!(output.value["catalog_digest"], startup_catalog.digest());

        let load = registry.descriptor(SKILL_LOAD_TOOL_NAME).unwrap().clone();
        let output = registry
            .dispatch(
                call(&load, serde_json::json!({"name": "zeta"})),
                "production",
            )
            .await
            .unwrap();
        assert_eq!(output.value["content"], "# zeta\nDo zeta.");
        assert_eq!(
            output.value["digest"],
            startup_catalog.get("zeta").unwrap().digest()
        );

        let maximum_content = format!("x{}", "\t".repeat(SKILL_CONTENT_MAX_BYTES - 1));
        let maximum = Arc::new(catalog(
            &serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "skills": [{
                    "name": "maximum",
                    "version": "1",
                    "description": "Maximum escaped output",
                    "content": maximum_content,
                }]
            }))
            .unwrap(),
        ));
        let mut maximum_registry = ToolRegistry::new();
        register_skill_tools(&mut maximum_registry, maximum).unwrap();
        let descriptor = maximum_registry
            .descriptor(SKILL_LOAD_TOOL_NAME)
            .unwrap()
            .clone();
        maximum_registry
            .dispatch(
                call(&descriptor, serde_json::json!({"name": "maximum"})),
                "production",
            )
            .await
            .expect("maximum escaped skill output must fit the tool envelope");
    }

    #[tokio::test]
    async fn load_fails_closed_for_unknown_skill_and_catalog_version_drift() {
        let startup_catalog = Arc::new(catalog(&sample("zeta", "alpha")));
        let mut registry = ToolRegistry::new();
        register_skill_tools(&mut registry, Arc::clone(&startup_catalog)).unwrap();
        let load = registry.descriptor(SKILL_LOAD_TOOL_NAME).unwrap().clone();

        let missing = registry
            .dispatch(
                call(&load, serde_json::json!({"name": "missing"})),
                "production",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            missing,
            RegistryError::Executor(ExecutorError::Failed { code, retryable: false, .. })
                if code == "skill_not_found"
        ));

        let changed = catalog(br#"{"version":1,"skills":[{"name":"alpha","version":"2","description":"Alpha","content":"changed"}]}"#);
        let changed_load = skill_tool_descriptors(&changed)[1].clone();
        let mismatch = registry
            .dispatch(
                call(&changed_load, serde_json::json!({"name": "alpha"})),
                "production",
            )
            .await
            .unwrap_err();
        assert_eq!(
            mismatch,
            RegistryError::ContractMismatch {
                field: "tool_version"
            }
        );
    }
}
