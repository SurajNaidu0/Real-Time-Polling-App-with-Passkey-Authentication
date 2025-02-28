use crate::error::WebauthnError;
use crate::startup::AppState;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use tower_sessions::Session;

use log::{error, info};

use webauthn_rs::prelude::*;
use mongodb::bson::{self, doc, Binary};
use mongodb::options::ReplaceOptions;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<mongodb::bson::oid::ObjectId>,
    pub username: String,
    pub keys: Passkey,
    #[serde(with = "uuid_binary_format")]
    pub uuid: Uuid,
}

pub async fn is_authenticated(session: &Session) -> Result<mongodb::bson::oid::ObjectId, WebauthnError> {
    let user_id = session.get::<mongodb::bson::oid::ObjectId>("user_id").await
        .map_err(|e| {
            error!("Session error: {:?}", e);
            WebauthnError::CorruptSession
        })?
        .ok_or_else(|| {
            info!("User not authenticated");
            WebauthnError::Unauthenticated
        })?;

    Ok(user_id)
}

// Custom serde module to convert Uuid to Binary and back
mod uuid_binary_format {
    use mongodb::bson::Binary;
    use mongodb::bson::spec::BinarySubtype;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use uuid::Uuid;

    pub fn serialize<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = uuid.as_bytes();
        let binary = Binary {
            subtype: BinarySubtype::Generic,
            bytes: bytes.to_vec(),
        };
        Binary::serialize(&binary, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let binary = Binary::deserialize(deserializer)?;
        let bytes: [u8; 16] = binary.bytes.as_slice().try_into().map_err(|_| {
            serde::de::Error::custom("Expected binary of length 16 for UUID")
        })?;
        Ok(Uuid::from_bytes(bytes))
    }
}

// REGISTRATION ENDPOINTS

pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Starting registration for user: {}", username);

    // Check if user already exists
    let user_collection = app_state.db.collection::<User>("users");
    let user_option = user_collection
        .find_one(doc! { "username": username.clone() }, None)
        .await
        .map_err(|e| {
            error!("Database error during user search: {:?}", e);
            WebauthnError::DatabaseError
        })?;

    if user_option.is_none() {
        // Generate a new unique ID for the user
        let user_unique_id = Uuid::new_v4();

        // Clear any previous registration state
        let _ = session.remove_value("reg_state").await;

        // Start WebAuthn registration process
        match app_state.webauthn.start_passkey_registration(
            user_unique_id,
            &username,
            &username,
            None,
        ) {
            Ok((ccr, reg_state)) => {
                // Store registration state in session
                session
                    .insert("reg_state", (username.clone(), user_unique_id, reg_state))
                    .await
                    .map_err(|e| {
                        error!("Session error: {:?}", e);
                        WebauthnError::CorruptSession
                    })?;

                info!("Registration challenge created for user: {}", username);
                Ok(Json(ccr))
            }
            Err(e) => {
                error!("WebAuthn registration initialization error: {:?}", e);
                Err(WebauthnError::Unknown)
            }
        }
    } else {
        info!("User '{}' already exists", username);
        Err(WebauthnError::UserExists)
    }
}

pub async fn finish_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    // Retrieve registration state from session
    let (username, user_unique_id, reg_state) = match session.get::<(String, Uuid, PasskeyRegistration)>("reg_state").await {
        Ok(Some(data)) => data,
        Ok(None) => {
            error!("No registration state found in session");
            return Err(WebauthnError::CorruptSession);
        }
        Err(e) => {
            error!("Failed to get session data: {:?}", e);
            return Err(WebauthnError::InvalidSessionState(e));
        }
    };

    // Clean up session
    let _ = session.remove_value("reg_state").await;

    // Complete the WebAuthn registration
    match app_state.webauthn.finish_passkey_registration(&reg, &reg_state) {
        Ok(passkey) => {
            let username_for_log = username.clone();

            // Create a new user document
            let user = User {
                id: None, // MongoDB will assign an _id
                username,
                keys: passkey,
                uuid: user_unique_id,
            };

            // Store the new user in MongoDB
            let user_collection = app_state.db.collection::<User>("users");
            match user_collection.insert_one(user, None).await {
                Ok(_) => {
                    info!("User registration completed successfully for: {}", username_for_log);
                    Ok(StatusCode::OK)
                }
                Err(e) => {
                    error!("Failed to store user in database: {:?}", e);
                    Err(WebauthnError::DatabaseError)
                }
            }
        }
        Err(e) => {
            error!("WebAuthn registration completion error: {:?}", e);
            Err(WebauthnError::InvalidCredential)
        }
    }
}

// AUTHENTICATION ENDPOINTS

pub async fn start_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Starting authentication for user: {}", username);

    // Clear any previous authentication state
    let _ = session.remove_value("auth_state").await;

    // Find user in database
    let user_collection = app_state.db.collection::<User>("users");
    let user = user_collection
        .find_one(doc! { "username": username.clone() }, None)
        .await
        .map_err(|e| {
            error!("Database error during user search: {:?}", e);
            WebauthnError::DatabaseError
        })?
        .ok_or_else(|| {
            info!("User '{}' not found", username);
            WebauthnError::UserNotFound
        })?;

    // Start authentication process with the user's passkey
    match app_state.webauthn.start_passkey_authentication(&[user.keys.clone()]) {
        Ok((rcr, auth_state)) => {
            // Store authentication state in session
            session
                .insert("auth_state", (user.uuid, auth_state))
                .await
                .map_err(|e| {
                    error!("Session error: {:?}", e);
                    WebauthnError::CorruptSession
                })?;

            info!("Authentication challenge created for user: {}", username);
            Ok(Json(rcr))
        }
        Err(e) => {
            error!("WebAuthn authentication initialization error: {:?}", e);
            Err(WebauthnError::Unknown)
        }
    }
}

pub async fn finish_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    // Retrieve authentication state from session
    let (user_uuid, auth_state): (Uuid, PasskeyAuthentication) = match session.get::<(Uuid, PasskeyAuthentication)>("auth_state").await {
        Ok(Some(data)) => data,
        Ok(None) => {
            error!("No authentication state found in session");
            return Err(WebauthnError::CorruptSession);
        }
        Err(e) => {
            error!("Failed to get session data: {:?}", e);
            return Err(WebauthnError::InvalidSessionState(e));
        }
    };

    // Clean up session
    let _ = session.remove_value("auth_state").await;

    // Find user in database
    let user_collection = app_state.db.collection::<User>("users");

    // Find user by UUID
    let binary = Binary {
        subtype: mongodb::bson::spec::BinarySubtype::Generic,
        bytes: user_uuid.as_bytes().to_vec(),
    };

    let user = user_collection
        .find_one(doc! { "uuid": binary }, None)
        .await
        .map_err(|e| {
            error!("Database error during user lookup: {:?}", e);
            WebauthnError::DatabaseError
        })?
        .ok_or_else(|| {
            error!("User with UUID {:?} not found", user_uuid);
            WebauthnError::UserNotFound
        })?;

    // Complete the WebAuthn authentication
    match app_state.webauthn.finish_passkey_authentication(&auth, &auth_state) {
        Ok(auth_result) => {
            // Update the credential counter in the database
            let mut updated_user = user.clone();
            updated_user.keys.update_credential(&auth_result);

            // Replace the user document
            let options = ReplaceOptions::builder().upsert(false).build();

            // Make sure we have an ID
            if let Some(id) = user.id {
                user_collection
                    .replace_one(
                        doc! { "_id": id },
                        updated_user,
                        options,
                    )
                    .await
                    .map_err(|e| {
                        error!("Failed to update user credential: {:?}", e);
                        WebauthnError::DatabaseError
                    })?;

                // Store user ID in session to mark them as authenticated
                session.insert("user_id", id).await.map_err(|e| {
                    error!("Failed to store user ID in session: {:?}", e);
                    WebauthnError::CorruptSession
                })?;

                info!("Authentication successful for user with UUID: {:?}", user_uuid);
                Ok(StatusCode::OK)
            } else {
                error!("User document is missing _id field");
                Err(WebauthnError::DatabaseError)
            }
        }
        Err(e) => {
            error!("WebAuthn authentication completion error: {:?}", e);
            Err(WebauthnError::InvalidCredential)
        }
    }
}