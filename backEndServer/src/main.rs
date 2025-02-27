use axum::{extract::Extension, http::StatusCode, response::IntoResponse, routing::post, Router};
use std::net::SocketAddr;

use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};
mod error;
use crate::startup::AppState;
use crate::auth::{start_register, finish_register, start_authentication, finish_authentication};

#[macro_use]
extern crate tracing;

mod auth;
mod startup;


#[tokio::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO");
    }
    // initialize tracing
    tracing_subscriber::fmt::init();

    // Create the app
    let app_state = AppState::new().await;

    let session_store = MemoryStore::default();

    //build our application with a route
    let app = Router::new()
        .route("/register_start/:username", post(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
        .layer(Extension(app_state))
        .layer(
            SessionManagerLayer::new(session_store)
                .with_name("webauthnrs")
                .with_same_site(SameSite::Strict)
                .with_secure(false) // TODO: change this to true when running on an HTTPS/production server instead of locally
                .with_expiry(Expiry::OnInactivity(Duration::seconds(360))),
        )
        .fallback(handler_404);

    let app = Router::new()
        .merge(app)
        .nest_service("/", tower_http::services::ServeDir::new("../frontEnd/js"));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Unable to spawn tcp listener");

    axum::serve(listener, app).await.unwrap();
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "nothing to see here")
}