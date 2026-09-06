use base64::Engine;
use common_enums::enums;
use common_utils::{errors::CustomResult, ext_traits::ValueExt};
use error_stack::ResultExt;
use hyperswitch_domain_models::router_data::ConnectorAuthType;
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{ExposeInterface, Secret};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::{Signer, Verifier},
    symm::{decrypt_aead, Cipher},
};
use serde::{Deserialize, Serialize};

type ConnectorResult<T> = CustomResult<T, errors::ConnectorError>;

#[derive(Clone)]
pub struct WechatpaycnAuthType {
    pub mch_id: Secret<String>,
    pub app_id: Secret<String>,
    pub merchant_private_key: Secret<String>,
    pub merchant_serial_no: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WechatpaycnAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match value {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                mch_id: api_key.clone(),
                app_id: key1.clone(),
                merchant_private_key: api_secret.clone(),
                merchant_serial_no: key2.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WechatpaycnMetadata {
    pub platform_public_key: Secret<String>,
    pub platform_key_id: Option<String>,
}

impl TryFrom<&Option<common_utils::pii::SecretSerdeValue>> for WechatpaycnMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: &Option<common_utils::pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        value
            .clone()
            .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata.platform_public_key",
            })?
            .parse_value("WechatpaycnMetadata")
            .change_context(errors::ConnectorError::InvalidConnectorConfig { config: "metadata" })
    }
}

fn pem(raw: &str, label: &str) -> String {
    let normalized = raw.trim().replace("\\n", "\n");
    if normalized.contains("-----BEGIN") {
        return normalized;
    }
    let compact: String = normalized.split_whitespace().collect();
    let body = compact
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----")
}

fn rsa_sign(private_key: &Secret<String>, message: &str) -> ConnectorResult<String> {
    let key =
        PKey::private_key_from_pem(pem(&private_key.clone().expose(), "PRIVATE KEY").as_bytes())
            .or_else(|_| {
                PKey::private_key_from_pem(
                    pem(&private_key.clone().expose(), "RSA PRIVATE KEY").as_bytes(),
                )
            })
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    signer
        .update(message.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(
        signer
            .sign_to_vec()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?,
    ))
}

pub fn authorization(
    auth: &WechatpaycnAuthType,
    method: &str,
    path_and_query: &str,
    body: &str,
) -> ConnectorResult<String> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let message = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        method.to_uppercase(),
        path_and_query,
        timestamp,
        nonce,
        body
    );
    let signature = rsa_sign(&auth.merchant_private_key, &message)?;
    Ok(format!(
        "WECHATPAY2-SHA256-RSA2048 mchid=\"{}\",nonce_str=\"{}\",timestamp=\"{}\",serial_no=\"{}\",signature=\"{}\"",
        auth.mch_id.clone().expose(),
        nonce,
        timestamp,
        auth.merchant_serial_no.clone().expose(),
        signature
    ))
}

pub fn verify_signature(public_key: &Secret<String>, message: &str, signature: &str) -> bool {
    let key = PKey::public_key_from_pem(pem(&public_key.clone().expose(), "PUBLIC KEY").as_bytes())
        .or_else(|_| {
            PKey::public_key_from_pem(
                pem(&public_key.clone().expose(), "RSA PUBLIC KEY").as_bytes(),
            )
        });
    let signature = base64::engine::general_purpose::STANDARD.decode(signature);
    match (key, signature) {
        (Ok(key), Ok(signature)) => Verifier::new(MessageDigest::sha256(), &key)
            .and_then(|mut verifier| {
                verifier.update(message.as_bytes())?;
                verifier.verify(&signature)
            })
            .unwrap_or(false),
        _ => false,
    }
}

pub fn verify_response(
    metadata: &WechatpaycnMetadata,
    headers: &http::HeaderMap,
    body: &[u8],
) -> ConnectorResult<bool> {
    let header = |name: &'static str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)
    };
    let timestamp = header("Wechatpay-Timestamp")?;
    let nonce = header("Wechatpay-Nonce")?;
    let signature = header("Wechatpay-Signature")?;
    if let Some(expected) = metadata.platform_key_id.as_deref() {
        let actual = header("Wechatpay-Serial")?;
        if actual != expected {
            return Ok(false);
        }
    }
    let body = std::str::from_utf8(body)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    Ok(verify_signature(
        &metadata.platform_public_key,
        &format!("{timestamp}\n{nonce}\n{body}\n"),
        signature,
    ))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NativeOrderResponse {
    pub code_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionResponse {
    pub appid: Option<String>,
    pub mchid: Option<String>,
    pub out_trade_no: String,
    pub transaction_id: Option<String>,
    pub trade_state: String,
    pub trade_state_desc: Option<String>,
}

impl TransactionResponse {
    pub fn status(&self) -> enums::AttemptStatus {
        match self.trade_state.as_str() {
            "SUCCESS" => enums::AttemptStatus::Charged,
            "NOTPAY" | "USERPAYING" => enums::AttemptStatus::AuthenticationPending,
            "CLOSED" | "REVOKED" => enums::AttemptStatus::Voided,
            "PAYERROR" => enums::AttemptStatus::Failure,
            "REFUND" => enums::AttemptStatus::AutoRefunded,
            _ => enums::AttemptStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefundResponse {
    pub refund_id: Option<String>,
    pub out_refund_no: String,
    pub out_trade_no: Option<String>,
    #[serde(alias = "refund_status")]
    pub status: String,
}

impl RefundResponse {
    pub fn status(&self) -> enums::RefundStatus {
        match self.status.as_str() {
            "SUCCESS" => enums::RefundStatus::Success,
            "CLOSED" | "ABNORMAL" => enums::RefundStatus::Failure,
            _ => enums::RefundStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotifyResource {
    pub algorithm: String,
    pub ciphertext: String,
    pub nonce: String,
    pub associated_data: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotifyEnvelope {
    pub id: String,
    pub event_type: String,
    pub resource_type: String,
    pub resource: NotifyResource,
    pub summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DecodedNotification {
    Payment(TransactionResponse),
    Refund(RefundResponse),
}

pub fn decrypt_notification(
    api_v3_key: &[u8],
    resource: &NotifyResource,
) -> ConnectorResult<DecodedNotification> {
    if api_v3_key.len() != 32 || resource.algorithm != "AEAD_AES_256_GCM" {
        return Err(errors::ConnectorError::WebhookBodyDecodingFailed.into());
    }
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&resource.ciphertext)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
    if encrypted.len() < 16 {
        return Err(errors::ConnectorError::WebhookBodyDecodingFailed.into());
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        api_v3_key,
        Some(resource.nonce.as_bytes()),
        resource.associated_data.as_bytes(),
        ciphertext,
        tag,
    )
    .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
    serde_json::from_slice(&plaintext)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_status_mapping() {
        let response = TransactionResponse {
            appid: None,
            mchid: None,
            out_trade_no: "order_1".to_string(),
            transaction_id: None,
            trade_state: "SUCCESS".to_string(),
            trade_state_desc: None,
        };
        assert_eq!(response.status(), enums::AttemptStatus::Charged);
    }

    #[test]
    fn refund_notification_uses_refund_status() {
        let notification: DecodedNotification = serde_json::from_str(
            r#"{"out_refund_no":"refund_1","out_trade_no":"order_1","refund_id":"5001","refund_status":"SUCCESS"}"#,
        )
        .expect("valid refund notification");
        match notification {
            DecodedNotification::Refund(refund) => {
                assert_eq!(refund.out_refund_no, "refund_1");
                assert_eq!(refund.status(), enums::RefundStatus::Success);
            }
            DecodedNotification::Payment(_) => panic!("expected refund notification"),
        }
    }
}
