use utoipa::ToSchema;

/// How a credential value is sourced at import time.
///
/// Inline stores the value directly (dev only). Env and File store
/// only a reference — the value is resolved from the environment or
/// filesystem at each import run, enabling K8s Secret rotation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum CredentialSource {
    /// Literal value stored in the database (development use only).
    Inline(String),
    /// Name of an environment variable read at import time.
    Env(String),
    /// Filesystem path to a file whose content is read at import time.
    File(String),
}

impl CredentialSource {
    /// Resolves the credential to its string value.
    pub fn resolve(&self) -> anyhow::Result<String> {
        match self {
            Self::Inline(v) => Ok(v.clone()),
            Self::Env(name) => {
                std::env::var(name).map_err(|e| anyhow::anyhow!("env var {name}: {e}"))
            }
            Self::File(path) => {
                std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("file {path}: {e}"))
            }
        }
    }
}

/// HTTP authentication method applied on each import request.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AuthMethod {
    /// HTTP Basic authentication.
    Basic {
        username: CredentialSource,
        password: CredentialSource,
    },
    /// Bearer token in the Authorization header.
    Bearer { token: CredentialSource },
    /// Arbitrary header/value pair (e.g. API key headers).
    ApiKey {
        header: String,
        value: CredentialSource,
    },
}

/// Authentication configuration for HTTP-based importers.
///
/// Wraps an [`AuthMethod`] whose credentials are resolved from
/// a [`CredentialSource`] at import time — not at configuration time.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
pub struct AuthConfig {
    pub method: AuthMethod,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that an Inline credential resolves to its literal value.
    #[test]
    fn credential_source_inline_resolves_to_value() {
        let src = CredentialSource::Inline("my-secret".into());
        assert_eq!(src.resolve().unwrap(), "my-secret");
    }

    /// Verifies that an Env credential reads the named environment variable.
    #[test]
    fn credential_source_env_reads_variable() {
        // Given an env var is set
        // SAFETY: test-only mutation, single-threaded test binary
        unsafe { std::env::set_var("TC6090_TEST_VAR", "env-value") };

        // When resolving
        let src = CredentialSource::Env("TC6090_TEST_VAR".into());

        // Then the value matches the env var
        assert_eq!(src.resolve().unwrap(), "env-value");
        // SAFETY: test-only mutation, single-threaded test binary
        unsafe { std::env::remove_var("TC6090_TEST_VAR") };
    }

    /// Verifies that an Env credential errors when the variable is not set.
    #[test]
    fn credential_source_env_errors_when_not_set() {
        // SAFETY: test-only mutation, single-threaded test binary
        unsafe { std::env::remove_var("TC6090_MISSING_VAR") };
        let src = CredentialSource::Env("TC6090_MISSING_VAR".into());
        assert!(src.resolve().is_err());
    }

    /// Verifies that a File credential reads file content.
    #[test]
    fn credential_source_file_reads_content() {
        // Given a temp file with known content
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "file-secret").unwrap();

        // When resolving
        let src = CredentialSource::File(path.to_string_lossy().into_owned());

        // Then the value matches file content
        assert_eq!(src.resolve().unwrap(), "file-secret");
    }

    /// Verifies that a File credential errors when the file does not exist.
    #[test]
    fn credential_source_file_errors_when_missing() {
        let src = CredentialSource::File("/nonexistent/path/secret.txt".to_string());
        assert!(src.resolve().is_err());
    }
}
