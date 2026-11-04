//! WAVLAKE PATCH (carried on top of upstream 0.25.0, `wavlake/spark-sdk`): the
//! secret shared with the one proxy allowed to speak for an address domain.
//!
//! The proxy checks that a wallet may hold a name before it forwards a
//! registration, but this server is also public on its own host, and a wallet
//! signature cannot show that the check ran. So `X-Forwarded-Host` and the
//! control plane (every route behind upstream's `auth` layer) are honoured only
//! for a request carrying the secret. Without a secret the server refuses to
//! start, unless a `dev` build is started with `--dev-no-forward-secret`.
//! Operator notes: the README's "Forward secret" section.

use anyhow::anyhow;
use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bitcoin::hashes::{Hash, sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::routes::FORWARDED_HOST_HEADER;

/// The header the trusted proxy carries the secret in.
pub const FORWARD_SECRET_HEADER: &str = "x-wavlake-forward-secret";

/// Shortest secret the server accepts. `openssl rand -hex 32` gives 64.
pub const MIN_FORWARD_SECRET_LEN: usize = 32;

/// Whom the server trusts to name the address domain and to use the control
/// plane.
#[derive(Clone)]
pub enum ForwardGate {
    /// Only a request carrying the secret. Holds its SHA-256, so a presented
    /// value of any length is compared in constant time.
    Required { digest: [u8; 32] },
    /// Every caller: upstream's behaviour plus the forwarded-host patch. Only a
    /// `dev` build can ask for it.
    Open,
}

impl ForwardGate {
    /// The gate for the configured secret, a blank one counting as none.
    /// `dev_open` asks for `Open` and is refused alongside a secret.
    pub fn from_config(secret: Option<&str>, dev_open: bool) -> Result<Self, anyhow::Error> {
        let secret = secret.map(str::trim).filter(|s| !s.is_empty());
        match (secret, dev_open) {
            (Some(_), true) => Err(anyhow!(
                "forward_secret and dev_no_forward_secret are both set: set one"
            )),
            (Some(secret), false) if secret.len() < MIN_FORWARD_SECRET_LEN => Err(anyhow!(
                "forward_secret must be at least {MIN_FORWARD_SECRET_LEN} characters (e.g. `openssl rand -hex 32`)"
            )),
            (Some(secret), false) => Ok(Self::Required {
                digest: digest(secret.as_bytes()),
            }),
            (None, true) => Ok(Self::Open),
            (None, false) => Err(anyhow!(
                "a forward secret is required: set --forward-secret (or BREEZ_LNURL_FORWARD_SECRET) to the value the address-domain proxy sends in {FORWARD_SECRET_HEADER}"
            )),
        }
    }

    /// Whether a request presenting `presented` came from the trusted proxy.
    fn trusts(&self, presented: Option<&HeaderValue>) -> bool {
        match self {
            Self::Open => true,
            Self::Required { digest: expected } => presented
                .is_some_and(|value| bool::from(digest(value.as_bytes())[..].ct_eq(&expected[..]))),
        }
    }
}

fn digest(value: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(value).to_byte_array()
}

/// Whether a request came from the trusted proxy.
#[derive(Clone, Copy)]
struct Trusted(bool);

/// Decides once per request whether it came from the trusted proxy. Removes
/// the secret header either way, and `X-Forwarded-Host` unless trusted.
pub async fn mark_trust(State(gate): State<ForwardGate>, mut req: Request, next: Next) -> Response {
    let headers = req.headers_mut();
    let presented = headers.remove(FORWARD_SECRET_HEADER);
    let trusted = gate.trusts(presented.as_ref());
    if !trusted {
        if presented.is_some() {
            // A proxy holding the wrong secret lands here on every request,
            // and its reads then 404. Never log the value.
            warn!("ignoring a forward secret that does not match this server's");
        }
        if headers.remove(FORWARDED_HOST_HEADER).is_some() {
            debug!("ignoring X-Forwarded-Host from a caller without the forward secret");
        }
    }
    req.extensions_mut().insert(Trusted(trusted));
    next.run(req).await
}

/// The control plane answers only the trusted proxy. Fails closed when
/// `mark_trust` did not run.
pub async fn require_trusted(req: Request, next: Next) -> Response {
    // CORS preflight carries no credentials, as in upstream's `auth`.
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    if req.extensions().get::<Trusted>().is_some_and(|t| t.0) {
        return next.run(req).await;
    }
    warn!(
        "refusing {} {}: not from the trusted proxy",
        req.method(),
        req.uri().path()
    );
    StatusCode::UNAUTHORIZED.into_response()
}

#[cfg(test)]
mod tests {
    use super::{FORWARD_SECRET_HEADER, ForwardGate, mark_trust, require_trusted};
    use crate::routes::Host;
    use axum::{
        Router,
        http::{HeaderMap, StatusCode},
        middleware,
        routing::{get, post},
    };

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    fn required() -> ForwardGate {
        ForwardGate::from_config(Some(SECRET), false).expect("valid secret")
    }

    #[test]
    fn a_secret_is_required_to_start() {
        assert!(ForwardGate::from_config(None, false).is_err());
        assert!(ForwardGate::from_config(Some(""), false).is_err());
        assert!(ForwardGate::from_config(Some("   "), false).is_err());
    }

    #[test]
    fn a_short_secret_is_refused() {
        let short = "a".repeat(super::MIN_FORWARD_SECRET_LEN - 1);
        assert!(ForwardGate::from_config(Some(&short), false).is_err());
        let enough = "a".repeat(super::MIN_FORWARD_SECRET_LEN);
        assert!(ForwardGate::from_config(Some(&enough), false).is_ok());
    }

    #[test]
    fn the_dev_switch_opens_the_gate_only_without_a_secret() {
        assert!(matches!(
            ForwardGate::from_config(None, true),
            Ok(ForwardGate::Open)
        ));
        assert!(ForwardGate::from_config(Some(SECRET), true).is_err());
    }

    #[test]
    fn only_the_exact_secret_is_trusted() {
        let gate = required();
        let value = |s: &str| axum::http::HeaderValue::from_str(s).expect("header value");
        assert!(gate.trusts(Some(&value(SECRET))));
        assert!(!gate.trusts(None));
        assert!(!gate.trusts(Some(&value(""))));
        assert!(!gate.trusts(Some(&value(&SECRET[1..]))));
        assert!(!gate.trusts(Some(&value(&format!("{SECRET}0")))));
        assert!(!gate.trusts(Some(&value(&SECRET.to_uppercase()))));
    }

    #[test]
    fn the_configured_secret_is_trimmed() {
        // A trailing newline from `echo` into Secret Manager must not lock the
        // proxy out; header values arrive without surrounding whitespace.
        let gate = ForwardGate::from_config(Some(&format!("{SECRET}\n")), false).expect("valid");
        let value = axum::http::HeaderValue::from_str(SECRET).expect("header value");
        assert!(gate.trusts(Some(&value)));
    }

    /// What a handler saw: the host it resolved and whether the secret reached it.
    async fn echo(Host(host): Host, headers: HeaderMap) -> String {
        format!("{host}|{}", headers.contains_key(FORWARD_SECRET_HEADER))
    }

    /// The control plane and a public read, layered as `main.rs` layers them.
    async fn serve(gate: ForwardGate) -> String {
        let app = Router::new()
            .route("/lnurlpay/{pubkey}", post(echo))
            .route_layer(middleware::from_fn(require_trusted))
            .route("/lnurlp/{identifier}", get(echo))
            .layer(middleware::from_fn_with_state(gate, mark_trust));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn call(base: &str, register: bool, headers: &[(&str, &str)]) -> (StatusCode, String) {
        let client = reqwest::Client::new();
        let mut request = if register {
            client.post(format!("{base}/lnurlpay/02abc"))
        } else {
            client.get(format!("{base}/lnurlp/alice"))
        };
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await.expect("request");
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        (status, response.text().await.unwrap_or_default())
    }

    #[tokio::test]
    async fn a_direct_registration_is_refused() {
        let base = serve(required()).await;
        let (status, _) = call(&base, true, &[("x-forwarded-host", "wavlake.com")]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_registration_with_the_wrong_secret_is_refused() {
        let base = serve(required()).await;
        let wrong = "f".repeat(64);
        let (status, _) = call(
            &base,
            true,
            &[
                ("x-forwarded-host", "wavlake.com"),
                (FORWARD_SECRET_HEADER, &wrong),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_proxy_registers_under_its_forwarded_host() {
        let base = serve(required()).await;
        let (status, body) = call(
            &base,
            true,
            &[
                ("x-forwarded-host", "wavlake.com"),
                (FORWARD_SECRET_HEADER, SECRET),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // The forwarded host is honoured and the secret never reaches the handler.
        assert_eq!(body, "wavlake.com|false");
    }

    #[tokio::test]
    async fn a_public_read_ignores_an_untrusted_forwarded_host() {
        let base = serve(required()).await;
        let (status, body) = call(&base, false, &[("x-forwarded-host", "wavlake.com")]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.starts_with("127.0.0.1:"),
            "expected the request's own Host, got {body}"
        );
    }

    #[tokio::test]
    async fn a_public_read_from_the_proxy_keys_on_its_forwarded_host() {
        let base = serve(required()).await;
        let (status, body) = call(
            &base,
            false,
            &[
                ("x-forwarded-host", "wavlake.com"),
                (FORWARD_SECRET_HEADER, SECRET),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "wavlake.com|false");
    }

    #[tokio::test]
    async fn the_open_gate_is_upstream_behaviour() {
        let gate = ForwardGate::from_config(None, true).expect("dev gate");
        let base = serve(gate).await;
        let (status, body) = call(&base, true, &[("x-forwarded-host", "wavlake.com")]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "wavlake.com|false");
    }

    #[tokio::test]
    async fn the_control_plane_fails_closed_without_the_marking_layer() {
        let app = Router::new()
            .route("/lnurlpay/{pubkey}", post(echo))
            .route_layer(middleware::from_fn(require_trusted));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (status, _) = call(
            &format!("http://{addr}"),
            true,
            &[(FORWARD_SECRET_HEADER, SECRET)],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
