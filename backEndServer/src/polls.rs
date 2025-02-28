use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use mongodb::{
    bson::{self, doc, oid::ObjectId, DateTime},
    Collection,
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;

use crate::auth::is_authenticated;
use crate::error::WebauthnError;
use crate::startup::AppState;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PollOption {
    pub id: String,  // Using String instead of ObjectId for simpler client-side handling
    pub text: String,
    pub votes: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Poll {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub title: String,
    pub options: Vec<PollOption>,
    pub creator_id: ObjectId,  // Reference to the User's _id
    pub created_at: DateTime,
    pub is_closed: bool,
    pub total_votes: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vote {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub poll_id: ObjectId,
    pub user_id: ObjectId,
    pub option_id: String,
    pub voted_at: DateTime,
}

// Request and response models for API endpoints

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePollRequest {
    pub title: String,
    pub options: Vec<String>,  // Just the text of each option
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VoteRequest {
    pub option_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PollResponse {
    pub id: String,
    pub title: String,
    pub options: Vec<PollOption>,
    pub creator_id: String,
    pub created_at: String,
    pub is_closed: bool,
    pub total_votes: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PollStatistics {
    pub total_votes: i32,
    pub options_data: Vec<OptionStatistics>,
    pub created_at: String,
    pub time_since_creation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OptionStatistics {
    pub id: String,
    pub text: String,
    pub votes: i32,
    pub percentage: f64,
}

pub async fn create_poll(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(poll_req): Json<CreatePollRequest>,
) -> Result<impl IntoResponse, WebauthnError> {
    // Check if user is authenticated
    let user_id = is_authenticated(&session).await?;

    // Validate poll data
    if poll_req.title.trim().is_empty() {
        return Err(WebauthnError::InvalidInput("Poll title cannot be empty".into()));
    }

    if poll_req.options.len() < 2 {
        return Err(WebauthnError::InvalidInput("Poll must have at least 2 options".into()));
    }

    // Check for duplicate options
    let mut unique_options = std::collections::HashSet::new();
    for option in &poll_req.options {
        if option.trim().is_empty() {
            return Err(WebauthnError::InvalidInput("Poll options cannot be empty".into()));
        }

        if !unique_options.insert(option.trim().to_lowercase()) {
            return Err(WebauthnError::InvalidInput("Duplicate poll options are not allowed".into()));
        }
    }

    // Create poll options
    let options: Vec<PollOption> = poll_req.options
        .iter()
        .map(|text| PollOption {
            id: Uuid::new_v4().to_string(),
            text: text.clone(),
            votes: 0,
        })
        .collect();

    // Create the poll document
    let poll = Poll {
        id: None, // MongoDB will assign an _id
        title: poll_req.title,
        options,
        creator_id: user_id,
        created_at: mongodb::bson::DateTime::now(),
        is_closed: false,
        total_votes: 0,
    };

    // Insert poll into database
    let poll_collection: Collection<Poll> = app_state.db.collection("polls");
    let result = poll_collection.insert_one(poll, None).await
        .map_err(|e| {
            error!("Failed to insert poll: {:?}", e);
            WebauthnError::DatabaseError
        })?;

    // Return the ID of the newly created poll
    let poll_id = result.inserted_id.as_object_id()
        .ok_or_else(|| {
            error!("Failed to get inserted poll ID");
            WebauthnError::DatabaseError
        })?;

    info!("Poll created with ID: {}", poll_id);

    Ok((StatusCode::CREATED, Json(doc! { "poll_id": poll_id.to_string() })))
}

