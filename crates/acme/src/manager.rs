//! Getting and renewing the certificate (RFC 8555): one certificate for
//! every name, HTTP-01 challenges answered by the port-80 server, the same
//! key for every renewal.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, HttpClient, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PublicKeyData};

use crate::cert::{self, Info};
use crate::certs::{Certs, certified_key, private_key, self_signed};
use crate::store::Store;
use crate::web::Challenges;

/// How often the certificate's age is looked at.
const CHECK_INTERVAL: Duration = Duration::from_secs(3600);
/// After a failure, wait 1 h, then 2 h, ... at most this. Let's Encrypt
/// allows 5 failed validations per name per hour, so even the first retry
/// stays well inside its limits.
const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);
/// One whole issuance may take this long.
const ISSUE_TIMEOUT: Duration = Duration::from_secs(600);

/// Makes a fresh HTTP client for each ACME session.
pub type HttpFactory = Arc<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

/// What to ask for, and from whom.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The ACME directory URL (RFC 8555 §7.1.1).
    pub directory: String,
    /// The account's contact address, without `mailto:`.
    pub contact: Option<String>,
    /// Every name the certificate covers, as A-labels: the host name
    /// first, then `mta-sts.<domain>` for each domain.
    pub names: Vec<String>,
}

/// Keeps a valid certificate in [`Certs`].
pub struct Manager {
    settings: Settings,
    store: Store,
    key: KeyPair,
    certs: Arc<Certs>,
    current: Mutex<Option<Info>>,
    challenges: Challenges,
    http: HttpFactory,
    poll_timeout: Duration,
}

impl std::fmt::Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manager")
            .field("settings", &self.settings)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl Manager {
    /// Loads the key and the stored certificate. Until a certificate for
    /// the right key exists, a self-signed one is served.
    pub fn new(
        settings: Settings,
        store: Store,
        challenges: Challenges,
        http: HttpFactory,
    ) -> Result<Self, String> {
        let hostname = settings
            .names
            .first()
            .ok_or("the certificate needs at least one name")?
            .clone();
        let key = store.key()?;
        let mut current = None;
        let mut first = None;
        match store.cert() {
            Ok(Some(pem)) => match load(&pem, &key) {
                Ok((ck, info)) => {
                    first = Some(ck);
                    current = Some(info);
                }
                Err(e) => tracing::warn!(
                    path = %store.cert_path().display(),
                    error = %e,
                    "ignoring the stored certificate; a new one will be requested"
                ),
            },
            Ok(None) => {}
            Err(e) => return Err(format!("{}: {e}", store.cert_path().display())),
        }
        let first = match first {
            Some(ck) => ck,
            None => {
                tracing::warn!(
                    "no ACME certificate yet: serving a self-signed one until it arrives"
                );
                self_signed(&hostname, &key)?
            }
        };
        Ok(Self {
            settings,
            store,
            key,
            certs: Certs::new(first),
            current: Mutex::new(current),
            challenges,
            http,
            poll_timeout: Duration::from_secs(120),
        })
    }

    /// How long to wait for the CA to validate or issue.
    pub fn with_poll_timeout(mut self, timeout: Duration) -> Self {
        self.poll_timeout = timeout;
        self
    }

    /// The certificate source for every TLS listener.
    pub fn certs(&self) -> Arc<Certs> {
        self.certs.clone()
    }

    /// The certificate in use, if it came from the CA.
    pub fn info(&self) -> Option<Info> {
        self.lock_current().clone()
    }

    /// Whether a new certificate is needed at `now` (Unix seconds): none
    /// yet, a name missing, or two thirds of its lifetime used up.
    pub fn due(&self, now: u64) -> bool {
        match &*self.lock_current() {
            None => true,
            Some(info) => {
                now >= info.renew_at() || !self.settings.names.iter().all(|n| info.covers(n))
            }
        }
    }

    /// Checks hourly and renews when due, backing off after failures.
    pub async fn run(self: Arc<Self>) {
        let mut failures: u32 = 0;
        loop {
            let mut wait = CHECK_INTERVAL;
            if self.due(unix_now()) {
                match tokio::time::timeout(ISSUE_TIMEOUT, self.renew()).await {
                    Ok(Ok(())) => failures = 0,
                    outcome => {
                        let error = match outcome {
                            Ok(Err(e)) => e,
                            _ => "timed out".into(),
                        };
                        failures = failures.saturating_add(1);
                        wait = backoff(failures);
                        tracing::error!(
                            names = ?self.settings.names,
                            error = %error,
                            retry_in_secs = wait.as_secs(),
                            "could not get a TLS certificate from the ACME CA"
                        );
                    }
                }
            }
            tokio::time::sleep(wait).await;
        }
    }

    /// Orders a certificate for every name and, once it checks out,
    /// stores it and starts serving it.
    pub async fn renew(&self) -> Result<(), String> {
        let account = self.account().await?;
        let mut tokens = Vec::new();
        let result = self.order(&account, &mut tokens).await;
        for t in &tokens {
            self.challenges.remove(t);
        }
        let pem = result?;

        let (ck, info) = load(pem.as_bytes(), &self.key)?;
        if let Some(missing) = self.settings.names.iter().find(|n| !info.covers(n)) {
            return Err(format!("the issued certificate does not cover {missing}"));
        }
        self.store
            .save_cert(pem.as_bytes())
            .map_err(|e| format!("{}: {e}", self.store.cert_path().display()))?;
        self.certs.set(ck);
        tracing::info!(
            names = ?info.names,
            not_after = info.not_after,
            "new TLS certificate from the ACME CA"
        );
        *self.lock_current() = Some(info);
        Ok(())
    }

    /// The stored account for this directory, or a new one.
    async fn account(&self) -> Result<Account, String> {
        let directory = &self.settings.directory;
        let acme = |e: instant_acme::Error| format!("ACME account at {directory}: {e}");
        let stored = self
            .store
            .account(directory)
            .map_err(|e| format!("reading the ACME account: {e}"))?;
        if let Some(json) = stored {
            let credentials: AccountCredentials = serde_json::from_slice(&json)
                .map_err(|e| format!("{}: {e}", self.store.account_path(directory).display()))?;
            return Account::builder_with_http((self.http)())
                .from_credentials(credentials)
                .await
                .map_err(acme);
        }
        let contact = self
            .settings
            .contact
            .as_ref()
            .map(|c| format!("mailto:{c}"));
        let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
        // The operator accepted the CA's terms in the configuration
        // (`acme.accept_terms`); RFC 8555 §7.3.
        let (account, credentials) = Account::builder_with_http((self.http)())
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.clone(),
                None,
            )
            .await
            .map_err(acme)?;
        let json = serde_json::to_vec(&credentials).map_err(|e| e.to_string())?;
        self.store
            .save_account(directory, &json)
            .map_err(|e| format!("saving the ACME account: {e}"))?;
        tracing::info!(directory = %directory, "created an ACME account");
        Ok(account)
    }

    /// Runs one order to the end and returns the PEM chain. Challenge
    /// tokens put up on the web server are added to `tokens`.
    async fn order(&self, account: &Account, tokens: &mut Vec<String>) -> Result<String, String> {
        let acme = |e: instant_acme::Error| e.to_string();
        let identifiers: Vec<Identifier> = self
            .settings
            .names
            .iter()
            .map(|n| Identifier::Dns(n.clone()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(acme)?;

        // RFC 8555 §7.5.1: answer each pending authorization.
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.map_err(acme)?;
            let name = authz.identifier().to_string();
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => return Err(format!("authorization for {name} is {other:?}")),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| format!("the CA offers no http-01 challenge for {name}"))?;
            // RFC 8555 §8.3: serve the key authorization at
            // /.well-known/acme-challenge/<token>.
            self.challenges
                .insert(&challenge.token, challenge.key_authorization().as_str());
            tokens.push(challenge.token.clone());
            challenge.set_ready().await.map_err(acme)?;
        }

        let retry = RetryPolicy::new()
            .initial_delay(Duration::from_millis(500))
            .backoff(1.5)
            .timeout(self.poll_timeout);
        let status = order.poll_ready(&retry).await.map_err(acme)?;
        if status != OrderStatus::Ready {
            return Err(format!("the order is {status:?}, not ready"));
        }
        let csr = csr(&self.settings.names, &self.key)?;
        order.finalize_csr(&csr).await.map_err(acme)?;
        order.poll_certificate(&retry).await.map_err(acme)
    }

    fn lock_current(&self) -> std::sync::MutexGuard<'_, Option<Info>> {
        match self.current.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// A PEM chain checked against our key.
fn load(pem: &[u8], key: &KeyPair) -> Result<(Arc<rustls::sign::CertifiedKey>, Info), String> {
    let chain = cert::chain(pem)?;
    let leaf = chain.first().ok_or("empty chain")?;
    let info = cert::inspect(leaf)?;
    if info.spki != key.subject_public_key_info() {
        return Err("the certificate is not for our key".into());
    }
    let ck = certified_key(chain, private_key(key))?;
    Ok((ck, info))
}

/// The certificate request: every name as a dNSName, no subject (the CA
/// takes the names from subjectAltName, RFC 8555 §7.4).
fn csr(names: &[String], key: &KeyPair) -> Result<Vec<u8>, String> {
    let mut params = CertificateParams::new(names.to_vec()).map_err(|e| e.to_string())?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(key)
        .map_err(|e| format!("certificate request: {e}"))?;
    Ok(csr.der().to_vec())
}

fn backoff(failures: u32) -> Duration {
    let hours = 1u64 << failures.saturating_sub(1).min(5);
    Duration::from_secs(hours * 3600).min(MAX_BACKOFF)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_a_day() {
        let h = |n| backoff(n).as_secs() / 3600;
        assert_eq!(
            [h(1), h(2), h(3), h(4), h(5), h(6), h(7), h(100)],
            [1, 2, 4, 8, 16, 24, 24, 24]
        );
    }
}
