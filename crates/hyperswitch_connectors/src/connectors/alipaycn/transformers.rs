use std::collections::BTreeMap;

use base64::Engine;
use common_enums::enums;
use common_utils::{errors::CustomResult, types::StringMajorUnit};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::{AlipayCnChannel, PaymentMethodData, WalletData},
    router_data::ConnectorAuthType,
    types::PaymentsAuthorizeRouterData,
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{ExposeInterface, Secret};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};

type ConnectorResult<T> = CustomResult<T, errors::ConnectorError>;

#[derive(Clone)]
pub struct AlipaycnAuthType {
    pub app_id: Secret<String>,
    pub alipay_public_key: Secret<String>,
    pub app_private_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AlipaycnAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match value {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                app_id: api_key.clone(),
                alipay_public_key: key1.clone(),
                app_private_key: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlipayProduct {
    Page,
    Wap,
}

impl AlipayProduct {
    fn method(self) -> &'static str {
        match self {
            Self::Page => "alipay.trade.page.pay",
            Self::Wap => "alipay.trade.wap.pay",
        }
    }

    fn product_code(self) -> &'static str {
        match self {
            Self::Page => "FAST_INSTANT_TRADE_PAY",
            Self::Wap => "QUICK_WAP_WAY",
        }
    }
}

pub fn product_from_request(data: &PaymentsAuthorizeRouterData) -> ConnectorResult<AlipayProduct> {
    match &data.request.payment_method_data {
        PaymentMethodData::Wallet(WalletData::AliPayRedirect(wallet)) => Ok(match wallet.channel {
            Some(AlipayCnChannel::Wap) => AlipayProduct::Wap,
            Some(AlipayCnChannel::Page) | None => AlipayProduct::Page,
        }),
        _ => Err(errors::ConnectorError::NotImplemented(
            "alipaycn supports wallet.alipay_redirect only".to_string(),
        )
        .into()),
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

pub fn sign_content(params: &BTreeMap<String, String>, exclude_sign_type: bool) -> String {
    params
        .iter()
        .filter(|(key, value)| {
            key.as_str() != "sign"
                && !value.is_empty()
                && !(exclude_sign_type && key.as_str() == "sign_type")
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn rsa2_sign(private_key: &Secret<String>, content: &str) -> ConnectorResult<String> {
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
        .update(content.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    let signature = signer
        .sign_to_vec()
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(signature))
}

pub fn verify_signature(public_key: &str, content: &str, signature: &str) -> bool {
    let key = PKey::public_key_from_pem(pem(public_key, "PUBLIC KEY").as_bytes())
        .or_else(|_| PKey::public_key_from_pem(pem(public_key, "RSA PUBLIC KEY").as_bytes()));
    let signature = base64::engine::general_purpose::STANDARD.decode(signature);
    match (key, signature) {
        (Ok(key), Ok(signature)) => Verifier::new(MessageDigest::sha256(), &key)
            .and_then(|mut verifier| {
                verifier.update(content.as_bytes())?;
                verifier.verify(&signature)
            })
            .unwrap_or(false),
        _ => false,
    }
}

pub fn verify_json_response(
    auth: &AlipaycnAuthType,
    body: &[u8],
    response_field: &str,
) -> ConnectorResult<bool> {
    // Alipay signs the exact JSON substring stored under `<method>_response`.
    // Parsing and serializing that object again can change whitespace and would
    // invalidate an otherwise correct signature, so retain its raw bytes here.
    let envelope: BTreeMap<String, Box<serde_json::value::RawValue>> = serde_json::from_slice(body)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    let content = envelope
        .get(response_field)
        .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;
    let signature_raw = envelope
        .get("sign")
        .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;
    let signature: String = serde_json::from_str(signature_raw.get())
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    Ok(verify_signature(
        &auth.alipay_public_key.clone().expose(),
        content.get(),
        &signature,
    ))
}

fn common_params(auth: &AlipaycnAuthType, method: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "app_id".to_string(),
            auth.app_id.clone().expose().to_string(),
        ),
        ("charset".to_string(), "utf-8".to_string()),
        ("format".to_string(), "JSON".to_string()),
        ("method".to_string(), method.to_string()),
        ("sign_type".to_string(), "RSA2".to_string()),
        (
            "timestamp".to_string(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        ),
        ("version".to_string(), "1.0".to_string()),
    ])
}

pub fn signed_request(
    auth: &AlipaycnAuthType,
    method: &str,
    biz_content: serde_json::Value,
    notify_url: Option<&str>,
    return_url: Option<&str>,
) -> ConnectorResult<BTreeMap<String, String>> {
    let mut params = common_params(auth, method);
    params.insert("biz_content".to_string(), biz_content.to_string());
    if let Some(value) = notify_url.filter(|value| !value.is_empty()) {
        params.insert("notify_url".to_string(), value.to_string());
    }
    if let Some(value) = return_url.filter(|value| !value.is_empty()) {
        params.insert("return_url".to_string(), value.to_string());
    }
    let signature = rsa2_sign(&auth.app_private_key, &sign_content(&params, false))?;
    params.insert("sign".to_string(), signature);
    Ok(params)
}

pub fn authorize_request(
    auth: &AlipaycnAuthType,
    data: &PaymentsAuthorizeRouterData,
    amount: StringMajorUnit,
) -> ConnectorResult<BTreeMap<String, String>> {
    let product = product_from_request(data)?;
    let subject = data
        .description
        .clone()
        .unwrap_or_else(|| "RE8CH order".to_string());
    let biz = serde_json::json!({
        "out_trade_no": data.connector_request_reference_id,
        "product_code": product.product_code(),
        "total_amount": amount,
        "subject": subject,
        "timeout_express": "30m"
    });
    signed_request(
        auth,
        product.method(),
        biz,
        data.request.webhook_url.as_deref(),
        data.request.router_return_url.as_deref(),
    )
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlipayTradeResponse {
    pub code: String,
    pub msg: Option<String>,
    pub sub_code: Option<String>,
    pub sub_msg: Option<String>,
    pub trade_no: Option<String>,
    pub out_trade_no: Option<String>,
    pub trade_status: Option<String>,
    pub refund_fee: Option<String>,
}

impl AlipayTradeResponse {
    pub fn is_success(&self) -> bool {
        self.code == "10000"
    }

    pub fn error_message(&self) -> String {
        self.sub_msg
            .clone()
            .or_else(|| self.msg.clone())
            .unwrap_or_else(|| "Alipay request failed".to_string())
    }

    pub fn payment_status(&self) -> enums::AttemptStatus {
        match self.trade_status.as_deref() {
            Some("TRADE_SUCCESS") | Some("TRADE_FINISHED") => enums::AttemptStatus::Charged,
            Some("WAIT_BUYER_PAY") => enums::AttemptStatus::AuthenticationPending,
            Some("TRADE_CLOSED") => enums::AttemptStatus::Voided,
            _ if self.is_success() => enums::AttemptStatus::Pending,
            _ => enums::AttemptStatus::Failure,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueryEnvelope {
    pub alipay_trade_query_response: AlipayTradeResponse,
    pub sign: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloseEnvelope {
    pub alipay_trade_close_response: AlipayTradeResponse,
    pub sign: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefundEnvelope {
    pub alipay_trade_refund_response: AlipayTradeResponse,
    pub sign: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefundQueryEnvelope {
    pub alipay_trade_fastpay_refund_query_response: AlipayTradeResponse,
    pub sign: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlipayWebhook {
    pub out_trade_no: String,
    pub trade_no: Option<String>,
    pub trade_status: String,
    pub sign: String,
    pub sign_type: Option<String>,
}

pub fn parse_webhook(body: &[u8]) -> ConnectorResult<(AlipayWebhook, BTreeMap<String, String>)> {
    let fields: BTreeMap<String, String> = serde_urlencoded::from_bytes(body)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
    let webhook: AlipayWebhook = serde_urlencoded::from_bytes(body)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
    Ok((webhook, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_content_is_sorted_and_excludes_signature() {
        let params = BTreeMap::from([
            ("z".to_string(), "last".to_string()),
            ("sign".to_string(), "secret".to_string()),
            ("a".to_string(), "first".to_string()),
            ("empty".to_string(), String::new()),
        ]);
        assert_eq!(sign_content(&params, false), "a=first&z=last");
    }
}
