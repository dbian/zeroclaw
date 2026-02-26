use super::traits::{Channel, ChannelMessage, SendMessage};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

/// Nextcloud Talk channel in webhook mode.
///
/// Incoming messages are received by the gateway endpoint `/nextcloud-talk`.
/// Outbound replies are sent through the Nextcloud Talk bot OCS API (`/bot/{token}/message`)
/// using HMAC-SHA256 request signing when a `bot_secret` is configured.
/// Falls back to bearer-auth on the standard `/chat/{token}` endpoint otherwise.
pub struct NextcloudTalkChannel {
    base_url: String,
    app_token: String,
    /// Shared bot secret used for HMAC signing of outgoing bot API requests.
    /// Same value as the webhook signature secret — set via `webhook_secret` in config
    /// or `ZEROCLAW_NEXTCLOUD_TALK_WEBHOOK_SECRET` env var.
    bot_secret: Option<String>,
    allowed_users: Vec<String>,
    client: reqwest::Client,
}

impl NextcloudTalkChannel {
    pub fn new(
        base_url: String,
        app_token: String,
        bot_secret: Option<String>,
        allowed_users: Vec<String>,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            app_token,
            bot_secret,
            allowed_users,
            client: reqwest::Client::new(),
        }
    }

    fn is_user_allowed(&self, actor_id: &str) -> bool {
        self.allowed_users.iter().any(|u| u == "*" || u == actor_id)
    }

    fn now_unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn parse_timestamp_secs(value: Option<&serde_json::Value>) -> u64 {
        let raw = match value {
            Some(serde_json::Value::Number(num)) => num.as_u64(),
            Some(serde_json::Value::String(s)) => s.trim().parse::<u64>().ok(),
            _ => None,
        }
        .unwrap_or_else(Self::now_unix_secs);

        // Some payloads use milliseconds.
        if raw > 1_000_000_000_000 {
            raw / 1000
        } else {
            raw
        }
    }

    fn value_to_string(value: Option<&serde_json::Value>) -> Option<String> {
        match value {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Number(n)) => Some(n.to_string()),
            _ => None,
        }
    }

    /// Parse a Nextcloud Talk webhook payload into channel messages.
    ///
    /// Supports two formats:
    ///
    /// **New ActivityPub format** (Nextcloud Talk v20+):
    /// - `type`: `"Create"`
    /// - `actor.id`: `"users/<username>"` (actor type prefix + username)
    /// - `actor.type`: `"Person"` (human) or `"Application"` (bot)
    /// - `object.id`: message ID
    /// - `object.name`: `"message"` for regular chat messages
    /// - `object.content`: JSON string `{"message":"...","parameters":[...]}`
    /// - `target.id`: room token
    ///
    /// **Legacy format**:
    /// - `type`: `"message"`
    /// - `object.token`: room token
    /// - `message.actorType`, `message.actorId`, `message.message`, `message.timestamp`
    pub fn parse_webhook_payload(&self, payload: &serde_json::Value) -> Vec<ChannelMessage> {
        let event_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");

        if event_type.eq_ignore_ascii_case("Create") {
            return self.parse_activitypub_payload(payload);
        }

        let mut messages = Vec::new();

        if !event_type.eq_ignore_ascii_case("message") {
            tracing::debug!("Nextcloud Talk: skipping non-message event: {event_type}");
            return messages;
        }

        let Some(message_obj) = payload.get("message") else {
            return messages;
        };

        let room_token = payload
            .get("object")
            .and_then(|obj| obj.get("token"))
            .and_then(|v| v.as_str())
            .or_else(|| message_obj.get("token").and_then(|v| v.as_str()))
            .map(str::trim)
            .filter(|token| !token.is_empty());

        let Some(room_token) = room_token else {
            tracing::warn!("Nextcloud Talk: missing room token in webhook payload");
            return messages;
        };

        let actor_type = message_obj
            .get("actorType")
            .and_then(|v| v.as_str())
            .or_else(|| payload.get("actorType").and_then(|v| v.as_str()))
            .unwrap_or("");

        // Ignore bot-originated messages to prevent feedback loops.
        if actor_type.eq_ignore_ascii_case("bots") {
            tracing::debug!("Nextcloud Talk: skipping bot-originated message");
            return messages;
        }

        let actor_id = message_obj
            .get("actorId")
            .and_then(|v| v.as_str())
            .or_else(|| payload.get("actorId").and_then(|v| v.as_str()))
            .map(str::trim)
            .filter(|id| !id.is_empty());

        let Some(actor_id) = actor_id else {
            tracing::warn!("Nextcloud Talk: missing actorId in webhook payload");
            return messages;
        };

        if !self.is_user_allowed(actor_id) {
            tracing::warn!(
                "Nextcloud Talk: ignoring message from unauthorized actor: {actor_id}. \
                Add to channels.nextcloud_talk.allowed_users in config.toml, \
                or run `zeroclaw onboard --channels-only` to configure interactively."
            );
            return messages;
        }

        let message_type = message_obj
            .get("messageType")
            .and_then(|v| v.as_str())
            .unwrap_or("comment");
        if !message_type.eq_ignore_ascii_case("comment") {
            tracing::debug!("Nextcloud Talk: skipping non-comment messageType: {message_type}");
            return messages;
        }

        // Ignore pure system messages.
        let has_system_message = message_obj
            .get("systemMessage")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        if has_system_message {
            tracing::debug!("Nextcloud Talk: skipping system message event");
            return messages;
        }

        let content = message_obj
            .get("message")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|content| !content.is_empty());

        let Some(content) = content else {
            return messages;
        };

        let message_id = Self::value_to_string(message_obj.get("id"))
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let timestamp = Self::parse_timestamp_secs(message_obj.get("timestamp"));

        messages.push(ChannelMessage {
            id: message_id,
            reply_target: room_token.to_string(),
            sender: actor_id.to_string(),
            content: content.to_string(),
            channel: "nextcloud_talk".to_string(),
            timestamp,
            thread_ts: None,
        });

        messages
    }

    /// Parse the new ActivityPub-style Nextcloud Talk webhook payload (type: "Create").
    ///
    /// Actor ID uses the format `"<actorType>/<username>"` (e.g. `"users/booting"`).
    /// The username part (after the last `/`) is used for allowlist checks, matching
    /// the `actorId` field in the legacy format.
    ///
    /// Message text is extracted from `object.content`, which is a JSON-encoded string
    /// with a `message` field: `{"message":"...","parameters":[...]}`.
    fn parse_activitypub_payload(&self, payload: &serde_json::Value) -> Vec<ChannelMessage> {
        let mut messages = Vec::new();

        let actor = payload.get("actor").unwrap_or(&serde_json::Value::Null);

        // Skip bot-originated messages (Application type) to prevent feedback loops.
        let actor_ap_type = actor.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if actor_ap_type.eq_ignore_ascii_case("Application") {
            tracing::debug!("Nextcloud Talk: skipping bot-originated message (ActivityPub format)");
            return messages;
        }

        // actor.id format is "<actorType>/<username>", e.g. "users/booting" or "bots/mybot".
        let actor_id_raw = actor.get("id").and_then(|v| v.as_str()).unwrap_or("");

        // Also skip when the actor type prefix is "bots".
        let actor_type_prefix = actor_id_raw.split('/').next().unwrap_or("");
        if actor_type_prefix.eq_ignore_ascii_case("bots") {
            tracing::debug!("Nextcloud Talk: skipping bot-originated message (bots prefix)");
            return messages;
        }

        // Extract the username (last component after the final '/').
        let actor_id = actor_id_raw
            .rsplit('/')
            .next()
            .map(str::trim)
            .filter(|id| !id.is_empty());

        let Some(actor_id) = actor_id else {
            tracing::warn!("Nextcloud Talk: missing actor id in ActivityPub payload");
            return messages;
        };

        if !self.is_user_allowed(actor_id) {
            tracing::warn!(
                "Nextcloud Talk: ignoring message from unauthorized actor: {actor_id}. \
                Add to channels.nextcloud_talk.allowed_users in config.toml, \
                or run `zeroclaw onboard --channels-only` to configure interactively."
            );
            return messages;
        }

        // Room token is in target.id.
        let room_token = payload
            .get("target")
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|t| !t.is_empty());

        let Some(room_token) = room_token else {
            tracing::warn!("Nextcloud Talk: missing room token in ActivityPub payload");
            return messages;
        };

        let object = payload.get("object").unwrap_or(&serde_json::Value::Null);

        // Only handle objects with name "message" (skip system/other events).
        let object_name = object.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if !object_name.eq_ignore_ascii_case("message") {
            tracing::debug!("Nextcloud Talk: skipping non-message object name: {object_name}");
            return messages;
        }

        // object.content is a JSON-encoded string: {"message":"...","parameters":[...]}.
        let content_raw = object.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let content =
            if let Ok(content_json) = serde_json::from_str::<serde_json::Value>(content_raw) {
                content_json
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(str::to_string)
            } else {
                // Fallback: use raw content string if it is not JSON-encoded.
                let trimmed = content_raw.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            };

        let Some(content) = content else {
            return messages;
        };

        let message_id =
            Self::value_to_string(object.get("id")).unwrap_or_else(|| Uuid::new_v4().to_string());
        let timestamp = Self::now_unix_secs();

        messages.push(ChannelMessage {
            id: message_id,
            reply_target: room_token.to_string(),
            sender: actor_id.to_string(),
            content,
            channel: "nextcloud_talk".to_string(),
            timestamp,
            thread_ts: None,
        });

        messages
    }

    /// Compute the HMAC-SHA256 bot request signature.
    ///
    /// `hex(hmac_sha256(secret, random + body))`
    fn sign_bot_request(secret: &str, random: &str, body: &str) -> String {
        let payload = format!("{random}{body}");
        // HMAC-SHA256 accepts any key length; this cannot fail in practice.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Send a message to the room using the bot API (`/bot/{token}/message`) with HMAC signing.
    async fn send_bot_message(
        &self,
        room_token: &str,
        content: &str,
        bot_secret: &str,
    ) -> anyhow::Result<()> {
        let encoded_room = urlencoding::encode(room_token);
        let url = format!(
            "{}/ocs/v2.php/apps/spreed/api/v1/bot/{}/message?format=json",
            self.base_url, encoded_room
        );

        let body_json = serde_json::to_string(&serde_json::json!({ "message": content }))
            .expect("serialising message body is infallible");
        let random = Uuid::new_v4().to_string();
        let signature = Self::sign_bot_request(bot_secret, &random, &body_json);

        tracing::debug!(
            room_token,
            url = %url,
            random = %random,
            content_len = content.len(),
            "Nextcloud Talk: sending via bot API"
        );

        let response = self
            .client
            .post(&url)
            .header("X-Nextcloud-Talk-Bot-Random", &random)
            .header("X-Nextcloud-Talk-Bot-Signature", &signature)
            .header("OCS-APIRequest", "true")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body_json)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(room_token, error = %e, "Nextcloud Talk: HTTP request failed");
                e
            })?;

        let status = response.status();
        let resp_body = response.text().await.unwrap_or_default();
        tracing::debug!(
            room_token,
            status = status.as_u16(),
            response = %resp_body,
            "Nextcloud Talk: bot API response"
        );

        if status.is_success() {
            tracing::info!(room_token, "Nextcloud Talk: message delivered via bot API");
            return Ok(());
        }

        let sanitized = crate::providers::sanitize_api_error(&resp_body);
        tracing::error!(
            room_token,
            status = status.as_u16(),
            error = %sanitized,
            "Nextcloud Talk: bot API send failed"
        );
        anyhow::bail!("Nextcloud Talk bot API error: {status}");
    }

    /// Send a message using the legacy OCS chat endpoint with bearer auth.
    async fn send_ocs_message(&self, room_token: &str, content: &str) -> anyhow::Result<()> {
        let encoded_room = urlencoding::encode(room_token);
        let url = format!(
            "{}/ocs/v2.php/apps/spreed/api/v1/chat/{}?format=json",
            self.base_url, encoded_room
        );

        tracing::debug!(
            room_token,
            url = %url,
            content_len = content.len(),
            "Nextcloud Talk: sending via OCS bearer auth"
        );

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.app_token)
            .header("OCS-APIRequest", "true")
            .header("Accept", "application/json")
            .json(&serde_json::json!({ "message": content }))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(room_token, error = %e, "Nextcloud Talk: HTTP request failed");
                e
            })?;

        let status = response.status();
        let resp_body = response.text().await.unwrap_or_default();
        tracing::debug!(
            room_token,
            status = status.as_u16(),
            response = %resp_body,
            "Nextcloud Talk: OCS API response"
        );

        if status.is_success() {
            tracing::info!(room_token, "Nextcloud Talk: message delivered via OCS API");
            return Ok(());
        }

        let sanitized = crate::providers::sanitize_api_error(&resp_body);
        tracing::error!(
            room_token,
            status = status.as_u16(),
            error = %sanitized,
            "Nextcloud Talk: OCS send failed"
        );
        anyhow::bail!("Nextcloud Talk API error: {status}");
    }

    async fn send_to_room(&self, room_token: &str, content: &str) -> anyhow::Result<()> {
        if let Some(ref secret) = self.bot_secret {
            self.send_bot_message(room_token, content, secret).await
        } else {
            self.send_ocs_message(room_token, content).await
        }
    }

    /// React to a message using the bot API.
    ///
    /// Requires `bot_secret` to be set (bots-v1 capability).
    /// POST `/ocs/v2.php/apps/spreed/api/v1/bot/{token}/reaction/{messageId}`
    pub async fn send_reaction(
        &self,
        room_token: &str,
        message_id: &str,
        reaction: &str,
    ) -> anyhow::Result<()> {
        let Some(ref bot_secret) = self.bot_secret else {
            anyhow::bail!("Nextcloud Talk: bot_secret required for send_reaction");
        };

        let encoded_room = urlencoding::encode(room_token);
        let encoded_msg = urlencoding::encode(message_id);
        let url = format!(
            "{}/ocs/v2.php/apps/spreed/api/v1/bot/{}/reaction/{}?format=json",
            self.base_url, encoded_room, encoded_msg
        );

        let body_json = serde_json::to_string(&serde_json::json!({ "reaction": reaction }))
            .expect("serialising reaction body is infallible");
        let random = Uuid::new_v4().to_string();
        let signature = Self::sign_bot_request(bot_secret, &random, &body_json);

        tracing::debug!(
            room_token,
            message_id,
            reaction,
            url = %url,
            "Nextcloud Talk: sending reaction via bot API"
        );

        let response = self
            .client
            .post(&url)
            .header("X-Nextcloud-Talk-Bot-Random", &random)
            .header("X-Nextcloud-Talk-Bot-Signature", &signature)
            .header("OCS-APIRequest", "true")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body_json)
            .send()
            .await?;

        let status = response.status();
        let resp_body = response.text().await.unwrap_or_default();
        tracing::debug!(
            room_token,
            message_id,
            status = status.as_u16(),
            response = %resp_body,
            "Nextcloud Talk: reaction API response"
        );

        if status.is_success() {
            return Ok(());
        }
        let sanitized = crate::providers::sanitize_api_error(&resp_body);
        tracing::error!(
            room_token,
            message_id,
            status = status.as_u16(),
            error = %sanitized,
            "Nextcloud Talk: reaction failed"
        );
        anyhow::bail!("Nextcloud Talk reaction API error: {status}");
    }

    /// Remove a previously added reaction from a message using the bot API.
    ///
    /// Requires `bot_secret` to be set (bots-v1 capability).
    /// DELETE `/ocs/v2.php/apps/spreed/api/v1/bot/{token}/reaction/{messageId}`
    pub async fn delete_reaction(
        &self,
        room_token: &str,
        message_id: &str,
        reaction: &str,
    ) -> anyhow::Result<()> {
        let Some(ref bot_secret) = self.bot_secret else {
            anyhow::bail!("Nextcloud Talk: bot_secret required for delete_reaction");
        };

        let encoded_room = urlencoding::encode(room_token);
        let encoded_msg = urlencoding::encode(message_id);
        let url = format!(
            "{}/ocs/v2.php/apps/spreed/api/v1/bot/{}/reaction/{}?format=json",
            self.base_url, encoded_room, encoded_msg
        );

        let body_json = serde_json::to_string(&serde_json::json!({ "reaction": reaction }))
            .expect("serialising reaction body is infallible");
        let random = Uuid::new_v4().to_string();
        let signature = Self::sign_bot_request(bot_secret, &random, &body_json);

        tracing::debug!(
            room_token,
            message_id,
            reaction,
            url = %url,
            "Nextcloud Talk: deleting reaction via bot API"
        );

        let response = self
            .client
            .delete(&url)
            .header("X-Nextcloud-Talk-Bot-Random", &random)
            .header("X-Nextcloud-Talk-Bot-Signature", &signature)
            .header("OCS-APIRequest", "true")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body_json)
            .send()
            .await?;

        let status = response.status();
        let resp_body = response.text().await.unwrap_or_default();
        tracing::debug!(
            room_token,
            message_id,
            status = status.as_u16(),
            response = %resp_body,
            "Nextcloud Talk: delete reaction API response"
        );

        if status.is_success() {
            return Ok(());
        }
        let sanitized = crate::providers::sanitize_api_error(&resp_body);
        tracing::error!(
            room_token,
            message_id,
            status = status.as_u16(),
            error = %sanitized,
            "Nextcloud Talk: delete reaction failed"
        );
        anyhow::bail!("Nextcloud Talk delete reaction API error: {status}");
    }
}

#[async_trait]
impl Channel for NextcloudTalkChannel {
    fn name(&self) -> &str {
        "nextcloud_talk"
    }

    async fn send(&self, message: &SendMessage) -> anyhow::Result<()> {
        self.send_to_room(&message.recipient, &message.content)
            .await
    }

    async fn listen(&self, _tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> anyhow::Result<()> {
        tracing::info!(
            "Nextcloud Talk channel active (webhook mode). \
            Configure Nextcloud Talk bot webhook to POST to your gateway's /nextcloud-talk endpoint."
        );

        // Keep task alive; incoming events are handled by the gateway webhook handler.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    async fn health_check(&self) -> bool {
        let url = format!("{}/status.php", self.base_url);

        self.client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

/// Verify Nextcloud Talk webhook signature.
///
/// Signature calculation (official Talk bot docs):
/// `hex(hmac_sha256(secret, X-Nextcloud-Talk-Random + raw_body))`
pub fn verify_nextcloud_talk_signature(
    secret: &str,
    random: &str,
    body: &str,
    signature: &str,
) -> bool {
    let random = random.trim();
    if random.is_empty() {
        tracing::warn!("Nextcloud Talk: missing X-Nextcloud-Talk-Random header");
        return false;
    }

    let signature_hex = signature
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(signature)
        .trim();

    let Ok(provided) = hex::decode(signature_hex) else {
        tracing::warn!("Nextcloud Talk: invalid signature format");
        return false;
    };

    let payload = format!("{random}{body}");
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(payload.as_bytes());

    mac.verify_slice(&provided).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_channel() -> NextcloudTalkChannel {
        NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["user_a".into()],
        )
    }

    #[test]
    fn nextcloud_talk_channel_name() {
        let channel = make_channel();
        assert_eq!(channel.name(), "nextcloud_talk");
    }

    #[test]
    fn nextcloud_talk_user_allowlist_exact_and_wildcard() {
        let channel = make_channel();
        assert!(channel.is_user_allowed("user_a"));
        assert!(!channel.is_user_allowed("user_b"));

        let wildcard = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        assert!(wildcard.is_user_allowed("any_user"));
    }

    #[test]
    fn nextcloud_talk_parse_valid_message_payload() {
        let channel = make_channel();
        let payload = serde_json::json!({
            "type": "message",
            "object": {
                "id": "42",
                "token": "room-token-123",
                "name": "Team Room",
                "type": "room"
            },
            "message": {
                "id": 77,
                "token": "room-token-123",
                "actorType": "users",
                "actorId": "user_a",
                "actorDisplayName": "User A",
                "timestamp": 1_735_701_200,
                "messageType": "comment",
                "systemMessage": "",
                "message": "Hello from Nextcloud"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "77");
        assert_eq!(messages[0].reply_target, "room-token-123");
        assert_eq!(messages[0].sender, "user_a");
        assert_eq!(messages[0].content, "Hello from Nextcloud");
        assert_eq!(messages[0].channel, "nextcloud_talk");
        assert_eq!(messages[0].timestamp, 1_735_701_200);
    }

    #[test]
    fn nextcloud_talk_parse_skips_non_message_events() {
        let channel = make_channel();
        let payload = serde_json::json!({
            "type": "room",
            "object": {"token": "room-token-123"},
            "message": {
                "actorType": "users",
                "actorId": "user_a",
                "message": "Hello"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_skips_bot_messages() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "message",
            "object": {"token": "room-token-123"},
            "message": {
                "actorType": "bots",
                "actorId": "bot_1",
                "message": "Self message"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_skips_unauthorized_sender() {
        let channel = make_channel();
        let payload = serde_json::json!({
            "type": "message",
            "object": {"token": "room-token-123"},
            "message": {
                "actorType": "users",
                "actorId": "user_b",
                "message": "Unauthorized"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_skips_system_message() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "message",
            "object": {"token": "room-token-123"},
            "message": {
                "actorType": "users",
                "actorId": "user_a",
                "messageType": "comment",
                "systemMessage": "joined",
                "message": ""
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_timestamp_millis_to_seconds() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "message",
            "object": {"token": "room-token-123"},
            "message": {
                "actorType": "users",
                "actorId": "user_a",
                "timestamp": 1_735_701_200_123_u64,
                "message": "hello"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].timestamp, 1_735_701_200);
    }

    // ── ActivityPub (new) format tests ──────────────────────────────────────

    #[test]
    fn nextcloud_talk_parse_activitypub_valid_message() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["booting".into()],
        );
        let payload = serde_json::json!({
            "type": "Create",
            "actor": {
                "type": "Person",
                "id": "users/booting",
                "name": "booting",
                "talkParticipantType": "1"
            },
            "object": {
                "type": "Note",
                "id": "700",
                "name": "message",
                "content": "{\"message\":\"上线了吗\",\"parameters\":[]}",
                "mediaType": "text/markdown"
            },
            "target": {
                "type": "Collection",
                "id": "2d2p7jh5",
                "name": "me and bot"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "700");
        assert_eq!(messages[0].reply_target, "2d2p7jh5");
        assert_eq!(messages[0].sender, "booting");
        assert_eq!(messages[0].content, "上线了吗");
        assert_eq!(messages[0].channel, "nextcloud_talk");
    }

    #[test]
    fn nextcloud_talk_parse_activitypub_skips_application_actor() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "Create",
            "actor": {
                "type": "Application",
                "id": "bots/zeroclaw_bot",
                "name": "zeroclaw_bot"
            },
            "object": {
                "type": "Note",
                "id": "701",
                "name": "message",
                "content": "{\"message\":\"bot reply\",\"parameters\":[]}",
                "mediaType": "text/markdown"
            },
            "target": {
                "type": "Collection",
                "id": "2d2p7jh5",
                "name": "me and bot"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_activitypub_skips_bots_prefix() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "Create",
            "actor": {
                "type": "Person",
                "id": "bots/mybot",
                "name": "mybot"
            },
            "object": {
                "type": "Note",
                "id": "702",
                "name": "message",
                "content": "{\"message\":\"auto msg\",\"parameters\":[]}",
                "mediaType": "text/markdown"
            },
            "target": {
                "type": "Collection",
                "id": "2d2p7jh5",
                "name": "test room"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_activitypub_skips_unauthorized_user() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["allowed_user".into()],
        );
        let payload = serde_json::json!({
            "type": "Create",
            "actor": {
                "type": "Person",
                "id": "users/other_user",
                "name": "other_user"
            },
            "object": {
                "type": "Note",
                "id": "703",
                "name": "message",
                "content": "{\"message\":\"hello\",\"parameters\":[]}",
                "mediaType": "text/markdown"
            },
            "target": {
                "type": "Collection",
                "id": "room-abc",
                "name": "chat"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_activitypub_skips_non_message_object() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "Create",
            "actor": {
                "type": "Person",
                "id": "users/user_a",
                "name": "user_a"
            },
            "object": {
                "type": "Note",
                "id": "704",
                "name": "reaction",
                "content": "{\"message\":\"👍\",\"parameters\":[]}",
                "mediaType": "text/markdown"
            },
            "target": {
                "type": "Collection",
                "id": "room-abc",
                "name": "chat"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert!(messages.is_empty());
    }

    #[test]
    fn nextcloud_talk_parse_activitypub_wildcard_allowlist() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            None,
            vec!["*".into()],
        );
        let payload = serde_json::json!({
            "type": "Create",
            "actor": {
                "type": "Person",
                "id": "users/any_user",
                "name": "any_user"
            },
            "object": {
                "type": "Note",
                "id": "705",
                "name": "message",
                "content": "{\"message\":\"hi there\",\"parameters\":[]}",
                "mediaType": "text/markdown"
            },
            "target": {
                "type": "Collection",
                "id": "room-xyz",
                "name": "channel"
            }
        });

        let messages = channel.parse_webhook_payload(&payload);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].sender, "any_user");
        assert_eq!(messages[0].content, "hi there");
        assert_eq!(messages[0].reply_target, "room-xyz");
    }

    const TEST_WEBHOOK_SECRET: &str = "nextcloud_test_webhook_secret";

    #[test]
    fn nextcloud_talk_signature_verification_valid() {
        let secret = TEST_WEBHOOK_SECRET;
        let random = "random-seed";
        let body = r#"{"type":"message"}"#;

        let payload = format!("{random}{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        assert!(verify_nextcloud_talk_signature(
            secret, random, body, &signature
        ));
    }

    #[test]
    fn nextcloud_talk_signature_verification_invalid() {
        assert!(!verify_nextcloud_talk_signature(
            TEST_WEBHOOK_SECRET,
            "random-seed",
            r#"{"type":"message"}"#,
            "deadbeef"
        ));
    }

    #[test]
    fn nextcloud_talk_signature_verification_accepts_sha256_prefix() {
        let secret = TEST_WEBHOOK_SECRET;
        let random = "random-seed";
        let body = r#"{"type":"message"}"#;

        let payload = format!("{random}{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        assert!(verify_nextcloud_talk_signature(
            secret, random, body, &signature
        ));
    }

    #[test]
    fn nextcloud_talk_sign_bot_request_deterministic() {
        let secret = TEST_WEBHOOK_SECRET;
        let random = "fixed-random";
        let body = r#"{"message":"hello"}"#;

        let sig1 = NextcloudTalkChannel::sign_bot_request(secret, random, body);
        let sig2 = NextcloudTalkChannel::sign_bot_request(secret, random, body);
        assert_eq!(sig1, sig2);
        assert!(!sig1.is_empty());

        // Changing the random must produce a different signature.
        let sig3 = NextcloudTalkChannel::sign_bot_request(secret, "other-random", body);
        assert_ne!(sig1, sig3);
    }

    #[test]
    fn nextcloud_talk_sign_bot_request_matches_incoming_verification() {
        let secret = TEST_WEBHOOK_SECRET;
        let random = "sync-random";
        let body = r#"{"message":"hi"}"#;

        // Outgoing signature produced by sign_bot_request…
        let outgoing_sig = NextcloudTalkChannel::sign_bot_request(secret, random, body);

        // …must pass the same verify_nextcloud_talk_signature used for incoming webhooks.
        assert!(verify_nextcloud_talk_signature(
            secret,
            random,
            body,
            &outgoing_sig
        ));
    }

    #[test]
    fn nextcloud_talk_has_bot_secret_when_provided() {
        let channel = NextcloudTalkChannel::new(
            "https://cloud.example.com".into(),
            "app-token".into(),
            Some("my-bot-secret".into()),
            vec!["*".into()],
        );
        assert!(channel.bot_secret.is_some());
    }

    #[test]
    fn nextcloud_talk_no_bot_secret_when_none() {
        let channel = make_channel();
        assert!(channel.bot_secret.is_none());
    }
}
