//! Authentication options for registry pulls.

use oci_client::secrets::RegistryAuth;

/// Credentials used when pulling an image from a registry.
#[derive(Debug, Clone, Default)]
pub enum Auth {
    /// Anonymous pull, no credentials.
    #[default]
    Anonymous,
    /// Bearer token (e.g. `OAuth2` token).
    BearerToken(String),
    /// HTTP Basic auth.
    Basic { user: String, pass: String },
}

impl Auth {
    /// Convert to the `oci-client` `RegistryAuth`.
    ///
    /// `oci-client` does not have a dedicated bearer-token variant; the
    /// upstream `Client::auth` method handles bearer flows internally when
    /// the registry responds with a 401. For a pre-fetched bearer token
    /// the cleanest mapping is to feed it as the password with a fixed
    /// `<token>` username, which is the convention `DockerHub` and most
    /// registries accept.
    pub(crate) fn into_registry_auth(self) -> RegistryAuth {
        match self {
            Self::Anonymous => RegistryAuth::Anonymous,
            Self::Basic { user, pass } => RegistryAuth::Basic(user, pass),
            Self::BearerToken(token) => RegistryAuth::Basic("<token>".into(), token),
        }
    }
}
