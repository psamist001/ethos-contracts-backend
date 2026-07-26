//! Webhook system for event push notifications (#65).
//!
//! Clients register a URL (and optional secret) to receive HTTP POST payloads
//! whenever a vault event occurs.  The delivery engine retries failed
//! deliveries with exponential back-off.
//!
//! # Architecture
//!
//! ```text
//! POST /webhooks            → register_webhook  (stores WebhookRegistration)
//! GET  /webhooks            → list_webhooks
//! DELETE /webhooks/:id      → delete_webhook
//! Internal: deliver_event() → called by handlers when events are emitted
//! ```

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Data types ────────────────────────────────────────────────────────────────

/// Events that can trigger webhook delivery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    VaultCreated,
    VaultCheckedIn,
    VaultReleased,
    VaultDeposit,
    VaultWithdrawal,
    BeneficiaryUpdated,
    VaultPaused,
    VaultResumed,
}

/// A persisted webhook subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistration {
    pub id: String,
    /// The HTTPS (or HTTP for local dev) URL to POST events to.
    pub url: String,
    /// Optional vault filter; `None` = receive events for all vaults.
    pub vault_id: Option<String>,
    /// Event types to deliver; empty = all event types.
    pub event_types: Vec<WebhookEventType>,
    /// HMAC-SHA256 secret used to sign payloads (optional).
    pub secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

/// Request body for `POST /webhooks`.
#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
    pub vault_id: Option<String>,
    #[serde(default)]
    pub event_types: Vec<WebhookEventType>,
    pub secret: Option<String>,
}

/// Payload sent to the registered URL on each event.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub id: String,
    pub event_type: WebhookEventType,
    pub vault_id: String,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

// ── In-memory store ───────────────────────────────────────────────────────────

pub type WebhookStore = Arc<Mutex<HashMap<String, WebhookRegistration>>>;

pub fn create_webhook_store() -> WebhookStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// ── Axum handler state ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WebhookState {
    pub store: WebhookStore,
    pub http_client: Client,
}

impl WebhookState {
    pub fn new() -> Self {
        Self {
            store: create_webhook_store(),
            http_client: Client::new(),
        }
    }
}

impl Default for WebhookState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `POST /webhooks` — register a new webhook endpoint.
pub async fn register_webhook(
    State(state): State<Arc<WebhookState>>,
    Json(body): Json<RegisterWebhookRequest>,
) -> Result<(StatusCode, Json<WebhookRegistration>), (StatusCode, Json<serde_json::Value>)> {
    if body.url.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "url must not be empty" })),
        ));
    }

    let registration = WebhookRegistration {
        id: Uuid::new_v4().to_string(),
        url: body.url,
        vault_id: body.vault_id,
        event_types: body.event_types,
        secret: body.secret,
        created_at: Utc::now(),
        active: true,
    };

    let mut store = state.store.lock().unwrap();
    store.insert(registration.id.clone(), registration.clone());

    Ok((StatusCode::CREATED, Json(registration)))
}

/// `GET /webhooks` — list all registered webhooks.
pub async fn list_webhooks(
    State(state): State<Arc<WebhookState>>,
) -> Json<Vec<WebhookRegistration>> {
    let store = state.store.lock().unwrap();
    let webhooks: Vec<WebhookRegistration> = store.values().cloned().collect();
    Json(webhooks)
}

/// `DELETE /webhooks/:id` — deactivate a webhook.
pub async fn delete_webhook(
    State(state): State<Arc<WebhookState>>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut store = state.store.lock().unwrap();
    if let Some(wh) = store.get_mut(&id) {
        wh.active = false;
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// ── Event delivery ────────────────────────────────────────────────────────────

/// Deliver `payload` to all matching active webhook registrations.
///
/// Each delivery is attempted asynchronously.  A failed request is retried up
/// to `MAX_RETRIES` times with exponential back-off before being dropped.
///
/// This function is fire-and-forget: it spawns a Tokio task per matching
/// webhook so that the calling handler is never blocked.
pub fn deliver_event(
    state: Arc<WebhookState>,
    event_type: WebhookEventType,
    vault_id: String,
    data: serde_json::Value,
) {
    let payload = WebhookPayload {
        id: Uuid::new_v4().to_string(),
        event_type: event_type.clone(),
        vault_id: vault_id.clone(),
        timestamp: Utc::now(),
        data,
    };

    let registrations: Vec<WebhookRegistration> = {
        let store = state.store.lock().unwrap();
        store
            .values()
            .filter(|wh| {
                if !wh.active {
                    return false;
                }
                // Filter by vault_id if specified.
                if let Some(ref wh_vault) = wh.vault_id {
                    if *wh_vault != vault_id {
                        return false;
                    }
                }
                // Filter by event type if a non-empty list is configured.
                if !wh.event_types.is_empty() && !wh.event_types.contains(&event_type) {
                    return false;
                }
                true
            })
            .cloned()
            .collect()
    };

    for registration in registrations {
        let client = state.http_client.clone();
        let payload_clone = payload.clone();

        tokio::spawn(async move {
            attempt_delivery(&client, &registration, &payload_clone).await;
        });
    }
}

// ── Internal delivery with retry ──────────────────────────────────────────────

const MAX_RETRIES: u32 = 4;
const BASE_DELAY_MS: u64 = 250;

async fn attempt_delivery(
    client: &Client,
    registration: &WebhookRegistration,
    payload: &WebhookPayload,
) {
    let body = match serde_json::to_string(payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(webhook_id = %registration.id, "Failed to serialize webhook payload: {e}");
            return;
        }
    };

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay_ms = BASE_DELAY_MS * (1 << (attempt - 1)); // 250, 500, 1000, 2000 ms
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        let mut req = client
            .post(&registration.url)
            .header("Content-Type", "application/json")
            .header("X-Ethos-Event", format!("{:?}", payload.event_type))
            .header("X-Ethos-Delivery", &payload.id)
            .body(body.clone());

        // Add HMAC-SHA256 signature header if a secret is configured.
        if let Some(ref secret) = registration.secret {
            let signature = sign_payload(&body, secret);
            req = req.header("X-Ethos-Signature", format!("sha256={signature}"));
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    webhook_id = %registration.id,
                    status = %resp.status(),
                    attempt,
                    "Webhook delivery succeeded"
                );
                return;
            }
            Ok(resp) => {
                tracing::warn!(
                    webhook_id = %registration.id,
                    status = %resp.status(),
                    attempt,
                    "Webhook delivery failed — will retry"
                );
            }
            Err(e) => {
                tracing::warn!(
                    webhook_id = %registration.id,
                    attempt,
                    "Webhook delivery error: {e} — will retry"
                );
            }
        }
    }

    tracing::error!(
        webhook_id = %registration.id,
        "Webhook delivery exhausted all retries — dropping"
    );
}

/// Compute HMAC-SHA256 hex signature over `body` using `secret`.
///
/// The signature is placed in the `X-Ethos-Signature: sha256=<hex>` header so
/// that receivers can verify authenticity using the shared secret.
fn sign_payload(body: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(body.as_bytes());
    let result = mac.finalize().into_bytes();

    result.iter().map(|b| format!("{b:02x}")).collect()
}
