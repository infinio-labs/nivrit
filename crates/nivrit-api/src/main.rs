mod auth;
mod config;
mod error;
mod handlers;
mod oauth_token;
mod rate_limit;
mod signing;
mod state;
mod tls;

use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, Method},
    routing::{delete, get, post},
    Router,
};
use axum_prometheus::PrometheusMetricLayer;
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tower_http::LatencyUnit;
use tracing::{info, Level};

use crate::{config::Config, state::AppState};

const REQUEST_ID_HEADER: &str = "x-request-id";

/// Cap request bodies. Secrets are client-encrypted blobs, not bulk uploads.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB
/// Hard ceiling on per-request handler time.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let config = Config::load()?;

    // Structured JSON logs for aggregators in production; human-readable in dev.
    if config.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_current_span(true)
            .with_env_filter(tracing_subscriber::EnvFilter::new(&config.log_level))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(&config.log_level))
            .init();
    }

    let state = AppState::from_config(&config).await?;

    // Prometheus metrics: the layer records HTTP request count / duration /
    // in-flight per route+method+status; the handle renders the /metrics text.
    let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();

    let cors = match config.cors_origin {
        Some(origin) => {
            let allowed: axum::http::HeaderValue =
                origin.parse().expect("invalid NIVRIT_CORS_ORIGIN");
            // Pin to the methods/headers the API actually uses rather than `Any`.
            CorsLayer::new()
                .allow_origin(allowed)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        }
        None => {
            tracing::warn!(
                "CORS is configured to allow any origin; set NIVRIT_CORS_ORIGIN in production"
            );
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        }
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route(
            "/metrics",
            get(move || std::future::ready(metric_handle.render())),
        )
        // Auth lives under /auth/*. There were once bare /register and /login
        // aliases as well; they were removed before 1.0 rather than supported
        // forever, since every other auth route was already namespaced.
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/login/totp", post(handlers::auth::login_totp))
        .route(
            "/auth/oauth/authorize",
            post(handlers::auth::oauth_authorize),
        )
        .route("/auth/oauth/callback", post(handlers::auth::oauth_callback))
        .route("/auth/oauth/setup", post(handlers::auth::oauth_setup))
        .route(
            "/auth/forgot-password",
            post(handlers::auth::forgot_password),
        )
        .route(
            "/auth/reset-password/verify",
            get(handlers::auth::verify_reset_token),
        )
        .route(
            "/auth/reset-password/begin",
            post(handlers::auth::reset_password_begin),
        )
        .route("/auth/reset-password", post(handlers::auth::reset_password))
        .route("/auth/totp/setup", post(handlers::auth::setup_totp))
        .route("/auth/totp/verify", post(handlers::auth::verify_totp))
        .route("/auth/totp/disable", post(handlers::auth::disable_totp))
        .route("/auth/pat", post(handlers::pat::create_pat))
        .route("/auth/pats", get(handlers::pat::list_pats))
        .route("/auth/pats/{token_id}", delete(handlers::pat::revoke_pat))
        .route("/orgs", post(handlers::orgs::create_org))
        .route(
            "/orgs/{org_id}/projects",
            get(handlers::orgs::list_org_projects),
        )
        .route("/projects", post(handlers::projects::create_project))
        .route(
            "/projects/{project_id}/environments",
            get(handlers::projects::list_environments).post(handlers::projects::create_environment),
        )
        .route(
            "/projects/{project_id}/environments/{environment_id}/members",
            get(handlers::projects::list_environment_overrides),
        )
        .route(
            "/projects/{project_id}/environments/{environment_id}/members/{user_id}",
            axum::routing::put(handlers::projects::set_environment_override)
                .delete(handlers::projects::remove_environment_override),
        )
        .route(
            "/projects/{project_id}/secrets",
            get(handlers::secrets::list_secrets).post(handlers::secrets::create_secret),
        )
        .route(
            "/projects/{project_id}/secrets/{key}",
            get(handlers::secrets::get_secret).delete(handlers::secrets::delete_secret),
        )
        .route(
            "/projects/{project_id}/secrets/{key}/versions",
            get(handlers::secrets::list_secret_versions),
        )
        .route(
            "/projects/{project_id}/secrets/{key}/reencrypt",
            axum::routing::put(handlers::secrets::reencrypt_secret),
        )
        .route(
            "/projects/{project_id}/secrets/{key}/restore",
            post(handlers::secrets::restore_secret),
        )
        .route(
            "/projects/{project_id}/folders",
            get(handlers::folders::list_folders).post(handlers::folders::create_folder),
        )
        .route(
            "/projects/{project_id}/folders/{folder_id}",
            axum::routing::delete(handlers::folders::delete_folder),
        )
        .route(
            "/projects/{project_id}/imports",
            get(handlers::imports::list_imports).post(handlers::imports::create_import),
        )
        .route(
            "/projects/{project_id}/imports/{import_id}",
            axum::routing::delete(handlers::imports::delete_import),
        )
        .route(
            "/projects/{project_id}/tags",
            get(handlers::tags::list_tags).post(handlers::tags::create_tag),
        )
        .route(
            "/projects/{project_id}/tags/{tag_id}",
            axum::routing::delete(handlers::tags::delete_tag),
        )
        .route(
            "/projects/{project_id}/secrets/{key}/tags",
            get(handlers::tags::list_secret_tags).post(handlers::tags::attach_secret_tag),
        )
        .route(
            "/projects/{project_id}/secrets/{key}/tags/{tag_id}",
            axum::routing::delete(handlers::tags::detach_secret_tag),
        )
        .route(
            "/projects/{project_id}/members",
            get(handlers::projects::list_members).post(handlers::projects::invite_member),
        )
        .route(
            "/projects/{project_id}/key-versions",
            get(handlers::projects::list_my_key_versions),
        )
        .route(
            "/projects/{project_id}/rotate-key",
            post(handlers::projects::rotate_key),
        )
        .route(
            "/projects/{project_id}/audit-logs",
            get(handlers::audit::list_access_logs),
        )
        .route(
            "/projects/{project_id}/audit-logs/{log_id}/verify",
            get(handlers::audit::verify_access_log),
        )
        .route(
            "/projects/{project_id}/audit-logs/verify-chain",
            get(handlers::audit::verify_access_log_chain),
        )
        .route("/users/public-key", get(handlers::users::get_public_key))
        .route("/users/me", get(handlers::users::get_me))
        .route("/users/me/orgs", get(handlers::users::get_my_orgs))
        .route("/users/me/projects", get(handlers::users::get_my_projects))
        .route("/users/me/rotate-key", post(handlers::users::rotate_key))
        // Layers are listed inner-to-outer; the last added runs first on a
        // request. Order: cors -> set request-id -> trace -> propagate id ->
        // metrics -> body limit -> timeout -> handler.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(prometheus_layer)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request| {
                    let request_id = req
                        .headers()
                        .get(REQUEST_ID_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    tracing::info_span!(
                        "http_request",
                        method = %req.method(),
                        path = %req.uri().path(),
                        request_id = %request_id,
                    )
                })
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::INFO)
                        .latency_unit(LatencyUnit::Millis),
                ),
        )
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(cors)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    match (config.tls_cert_path, config.tls_key_path) {
        (Some(cert), Some(key)) => {
            let tls_config = tls::build_tls_config(&cert, &key)?;
            info!(
                "nivrit-api listening on https://{} (TLS 1.3 only, post-quantum hybrid key exchange preferred)",
                addr
            );
            let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                // Allow in-flight requests up to REQUEST_TIMEOUT to drain.
                shutdown_handle.graceful_shutdown(Some(REQUEST_TIMEOUT));
            });
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        (None, None) => {
            info!("nivrit-api listening on http://{}", addr);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        }
        _ => anyhow::bail!("both tls_cert_path and tls_key_path must be set to enable TLS"),
    }

    Ok(())
}

/// Liveness: process is up. Cheap and dependency-free so a DB blip can't trigger
/// a restart storm.
async fn health() -> &'static str {
    "ok"
}

/// Readiness: the API can actually serve traffic (DB reachable).
async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::http::StatusCode {
    match state.db.ping().await {
        Ok(()) => axum::http::StatusCode::OK,
        Err(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Resolve when the process receives SIGTERM (containers) or Ctrl-C.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received; draining connections");
}
