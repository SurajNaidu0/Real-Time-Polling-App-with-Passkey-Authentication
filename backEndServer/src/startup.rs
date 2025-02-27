use std::collections::HashMap;
use std::sync::Arc;
// Removed unused Data struct that uses Mutex
use webauthn_rs::prelude::*;
use mongodb::{Client, Database};
// Removed unused imports

#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub db: Database,
}

impl AppState {
    pub async fn new() -> Self {
        let client = Client::with_uri_str("mongodb+srv://suraj:suraj@cluster0.pbka6.mongodb.net/")
            .await
            .expect("Failed to connect to MongoDB");
        let db = client.database("auth_db");

        let rp_id = "localhost";
        let rp_origin = Url::parse("http://localhost:8080").expect("Invalid URL");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
        let builder = builder.rp_name("Axum Webauthn-rs");
        let webauthn = Arc::new(builder.build().expect("Invalid configuration"));
        println!("Connected to MongoDB");
        AppState { webauthn, db }
    }
}