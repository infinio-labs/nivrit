use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_core::Role;
use nivrit_db::queries;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::CurrentUser,
    error::ApiError,
    handlers::authz::{require_project_member, require_role},
    signing::{entry_hash, AuditLogMessage, SignatureService, SignedAuditLog},
    state::AppState,
};

type ApiResult<T> = std::result::Result<T, ApiError>;

const DEFAULT_LOG_LIMIT: i64 = 100;
const MAX_LOG_LIMIT: i64 = 1000;

#[derive(Debug, Deserialize)]
pub struct ListAccessLogsQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AccessLogEntry {
    pub id: String,
    pub project_id: String,
    pub environment_id: Option<String>,
    pub secret_id: Option<String>,
    pub user_id: String,
    pub action: String,
    pub key: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
    pub signature_algorithm: Option<String>,
    pub signature: Option<String>,
    pub signing_public_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyAccessLogResponse {
    pub valid: bool,
    pub reason: Option<String>,
}

pub async fn list_access_logs(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<ListAccessLogsQuery>,
) -> ApiResult<Json<Vec<AccessLogEntry>>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Admin)?;

    let limit = query
        .limit
        .map(|l| l.clamp(1, MAX_LOG_LIMIT))
        .unwrap_or(DEFAULT_LOG_LIMIT);

    let rows = queries::list_access_logs(&state.db, project_id, limit).await?;

    Ok(Json(
        rows.into_iter()
            .map(|row| AccessLogEntry {
                id: row.id.to_string(),
                project_id: row.project_id.to_string(),
                environment_id: row.environment_id.map(|id| id.to_string()),
                secret_id: row.secret_id.map(|id| id.to_string()),
                user_id: row.user_id.to_string(),
                action: row.action,
                key: row.key,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                created_at: row.created_at.to_rfc3339(),
                signature_algorithm: row.signature_algorithm,
                signature: row.signature.map(|b| STANDARD.encode(&b)),
                signing_public_key: row.signing_public_key.map(|b| STANDARD.encode(&b)),
            })
            .collect(),
    ))
}

pub async fn verify_access_log(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, log_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> ApiResult<Json<VerifyAccessLogResponse>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Admin)?;

    let row = queries::get_access_log(&state.db, project_id, log_id).await?;

    let Some(algorithm) = row.signature_algorithm else {
        return Ok(Json(VerifyAccessLogResponse {
            valid: false,
            reason: Some("audit log entry is not signed".into()),
        }));
    };
    let Some(signature) = row.signature else {
        return Ok(Json(VerifyAccessLogResponse {
            valid: false,
            reason: Some("audit log signature is missing".into()),
        }));
    };
    let Some(public_key) = row.signing_public_key else {
        return Ok(Json(VerifyAccessLogResponse {
            valid: false,
            reason: Some("audit log signing public key is missing".into()),
        }));
    };

    let msg = AuditLogMessage::new(
        row.project_id,
        row.environment_id,
        row.user_id,
        &row.action,
        &row.key,
        row.created_at,
        row.prev_hash.as_deref(),
    );

    let signed = crate::signing::SignedAuditLog {
        algorithm,
        signature,
        public_key,
    };

    match SignatureService::verify_audit_log(&msg, &signed) {
        Ok(()) => Ok(Json(VerifyAccessLogResponse {
            valid: true,
            reason: None,
        })),
        Err(e) => Ok(Json(VerifyAccessLogResponse {
            valid: false,
            reason: Some(e.to_string()),
        })),
    }
}

/// Where a project's audit-log chain first fails to verify.
#[derive(Debug, Serialize)]
pub struct ChainBreak {
    pub chain_seq: i64,
    pub log_id: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyAccessLogChainResponse {
    pub total_entries: usize,
    pub valid: bool,
    pub first_break: Option<ChainBreak>,
}

/// Verify a whole project's audit-log chain, not just one entry.
///
/// [`verify_access_log`] proves a single row's *content* wasn't altered since
/// signing; it says nothing about whether a row was deleted or reordered,
/// because a lone signature has nothing to compare against. This walks every
/// entry in `chain_seq` order and checks that each one's `prev_hash` matches
/// the previous entry's recomputed hash and that the sequence has no gaps --
/// either of which a deletion or splice would break.
pub async fn verify_access_log_chain(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<VerifyAccessLogChainResponse>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Admin)?;

    let rows = queries::list_access_log_chain(&state.db, project_id).await?;
    let total_entries = rows.len();
    let mut expected_seq: i64 = 1;
    let mut expected_prev: Option<Vec<u8>> = None;
    let mut first_break = None;

    for row in &rows {
        if row.entry_hash.is_none() {
            // Predates chaining (backfilled at migration time). Not
            // independently verifiable, but not a break either -- move the
            // sequence anchor past it so later, chained entries are still
            // checked against each other rather than against a row that never
            // had a hash to link to.
            expected_seq = row.chain_seq + 1;
            expected_prev = None;
            continue;
        }

        if row.chain_seq != expected_seq {
            first_break = Some(ChainBreak {
                chain_seq: expected_seq,
                log_id: row.id.to_string(),
                reason: format!(
                    "expected chain_seq {expected_seq}, found {} -- an entry was likely deleted",
                    row.chain_seq
                ),
            });
            break;
        }

        if row.prev_hash != expected_prev {
            first_break = Some(ChainBreak {
                chain_seq: row.chain_seq,
                log_id: row.id.to_string(),
                reason: "prev_hash does not match the previous entry's hash -- the chain was tampered with or reordered".into(),
            });
            break;
        }

        let msg = AuditLogMessage::new(
            row.project_id,
            row.environment_id,
            row.user_id,
            &row.action,
            &row.key,
            row.created_at,
            row.prev_hash.as_deref(),
        );

        let recomputed = match (
            &row.signature_algorithm,
            &row.signature,
            &row.signing_public_key,
        ) {
            (Some(alg), Some(sig), Some(pk)) => {
                let signed = SignedAuditLog {
                    algorithm: alg.clone(),
                    signature: sig.clone(),
                    public_key: pk.clone(),
                };
                if SignatureService::verify_audit_log(&msg, &signed).is_err() {
                    first_break = Some(ChainBreak {
                        chain_seq: row.chain_seq,
                        log_id: row.id.to_string(),
                        reason: "signature verification failed".into(),
                    });
                    break;
                }
                entry_hash(&msg, Some(&signed))
            }
            _ => entry_hash(&msg, None),
        };

        match recomputed {
            Ok(h) if Some(&h) == row.entry_hash.as_ref() => {}
            Ok(_) => {
                first_break = Some(ChainBreak {
                    chain_seq: row.chain_seq,
                    log_id: row.id.to_string(),
                    reason: "stored entry_hash does not match the recomputed hash -- this entry was tampered with".into(),
                });
                break;
            }
            Err(e) => {
                first_break = Some(ChainBreak {
                    chain_seq: row.chain_seq,
                    log_id: row.id.to_string(),
                    reason: format!("failed to recompute chain hash: {e}"),
                });
                break;
            }
        }

        expected_seq = row.chain_seq + 1;
        expected_prev = row.entry_hash.clone();
    }

    Ok(Json(VerifyAccessLogChainResponse {
        total_entries,
        valid: first_break.is_none(),
        first_break,
    }))
}
