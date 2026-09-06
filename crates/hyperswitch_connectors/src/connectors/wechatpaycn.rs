pub mod transformers;

use std::sync::LazyLock;

use common_enums::enums;
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    api::WebhookResponse,
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData, PaymentsSyncData,
        RefundsData, ResponseId, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentsResponseData, RefundsResponseData, SupportedPaymentMethods,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsSyncRouterData,
        RefundSyncRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorIntegration, ConnectorSpecifications, ConnectorValidation,
    },
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    webhooks,
};
use hyperswitch_masking::{ExposeInterface, Secret};

use self::transformers as wechat;
use crate::utils::PaymentsSyncRequestData;

#[derive(Clone)]
pub struct Wechatpaycn;

impl Wechatpaycn {
    pub fn new() -> &'static Self {
        &Self
    }

    fn auth(
        &self,
        value: &ConnectorAuthType,
    ) -> CustomResult<wechat::WechatpaycnAuthType, errors::ConnectorError> {
        wechat::WechatpaycnAuthType::try_from(value)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)
    }

    fn signed_request(
        &self,
        auth: &ConnectorAuthType,
        base_url: &str,
        method: Method,
        path_and_query: &str,
        body: Option<serde_json::Value>,
    ) -> CustomResult<Request, errors::ConnectorError> {
        let auth = self.auth(auth)?;
        let body_string = body.map(|value| value.to_string()).unwrap_or_default();
        let method_name = match method {
            Method::Get => "GET",
            Method::Post => "POST",
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "wechatpaycn HTTP method".to_string(),
                )
                .into())
            }
        };
        let authorization =
            wechat::authorization(&auth, method_name, path_and_query, &body_string)?;
        let mut builder = RequestBuilder::new()
            .method(method)
            .url(&format!(
                "{}{}",
                base_url.trim_end_matches('/'),
                path_and_query
            ))
            .attach_default_headers()
            .headers(vec![
                ("Accept".to_string(), "application/json".to_string().into()),
                (
                    "Content-Type".to_string(),
                    "application/json".to_string().into(),
                ),
                ("Authorization".to_string(), authorization.into()),
            ]);
        if !body_string.is_empty() {
            builder = builder.set_body(RequestContent::RawBytes(body_string.into_bytes()));
        }
        Ok(builder.build())
    }

    fn verify_response<T>(
        &self,
        data: &T,
        metadata: &Option<common_utils::pii::SecretSerdeValue>,
        res: &Response,
    ) -> CustomResult<(), errors::ConnectorError> {
        let metadata = wechat::WechatpaycnMetadata::try_from(metadata)?;
        let headers = res
            .headers
            .as_ref()
            .ok_or(errors::ConnectorError::ResponseHandlingFailed)?;
        if !wechat::verify_response(&metadata, headers, &res.response)? {
            return Err(errors::ConnectorError::WebhookSourceVerificationFailed.into());
        }
        let _ = data;
        Ok(())
    }

    fn transaction_response(
        id: String,
        metadata: Option<serde_json::Value>,
    ) -> PaymentsResponseData {
        PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(id),
            redirection_data: Box::new(None),
            mandate_reference: Box::new(None),
            connector_metadata: metadata,
            network_txn_id: None,
            network_txn_link_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            authentication_data: None,
            charges: None,
        }
    }

    fn error_response(&self, res: Response) -> ErrorResponse {
        let parsed = serde_json::from_slice::<wechat::ErrorResponse>(&res.response).ok();
        ErrorResponse {
            status_code: res.status_code,
            code: parsed
                .as_ref()
                .map(|error| error.code.clone())
                .unwrap_or_else(|| "WECHATPAY_ERROR".to_string()),
            message: parsed
                .as_ref()
                .map(|error| error.message.clone())
                .unwrap_or_else(|| "WeChat Pay request failed".to_string()),
            reason: parsed.map(|error| error.message),
            attempt_status: None,
            connector_transaction_id: None,
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        }
    }
}

impl api::Payment for Wechatpaycn {}
impl api::PaymentSession for Wechatpaycn {}
impl api::ConnectorAccessToken for Wechatpaycn {}
impl api::MandateSetup for Wechatpaycn {}
impl api::PaymentAuthorize for Wechatpaycn {}
impl api::PaymentSync for Wechatpaycn {}
impl api::PaymentCapture for Wechatpaycn {}
impl api::PaymentVoid for Wechatpaycn {}
impl api::Refund for Wechatpaycn {}
impl api::RefundExecute for Wechatpaycn {}
impl api::RefundSync for Wechatpaycn {}
impl api::PaymentToken for Wechatpaycn {}
impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Wechatpaycn
{
}

impl ConnectorCommon for Wechatpaycn {
    fn id(&self) -> &'static str {
        "wechatpaycn"
    }
    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }
    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.wechatpaycn.base_url.as_ref()
    }
    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Ok(self.error_response(res))
    }
}

impl ConnectorValidation for Wechatpaycn {
    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Wechatpaycn {}
impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Wechatpaycn {}
impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>
    for Wechatpaycn
{
}
impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Wechatpaycn {}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Wechatpaycn {
    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        if req.request.currency != enums::Currency::CNY {
            return Err(errors::ConnectorError::NotSupported {
                message: "wechatpaycn only supports CNY".to_string(),
                connector: "wechatpaycn",
            }
            .into());
        }
        if !matches!(
            req.request.payment_method_data,
            PaymentMethodData::Wallet(WalletData::WeChatPayQr(_))
        ) {
            return Err(errors::ConnectorError::NotImplemented(
                "wechatpaycn supports wallet.we_chat_pay_qr only".to_string(),
            )
            .into());
        }
        let auth = self.auth(&req.connector_auth_type)?;
        let body = serde_json::json!({
            "appid": auth.app_id.expose(),
            "mchid": auth.mch_id.expose(),
            "description": req.description.clone().unwrap_or_else(|| "RE8CH order".to_string()),
            "out_trade_no": req.connector_request_reference_id,
            "notify_url": req.request.webhook_url,
            "amount": { "total": req.request.minor_amount, "currency": "CNY" }
        });
        Ok(Some(self.signed_request(
            &req.connector_auth_type,
            self.base_url(connectors),
            Method::Post,
            "/v3/pay/transactions/native",
            Some(body),
        )?))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        self.verify_response(data, &data.connector_meta_data, &res)?;
        let response: wechat::NativeOrderResponse = res
            .response
            .parse_struct("WechatNativeOrderResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&response));
        let mut output = data.clone();
        output.status = enums::AttemptStatus::AuthenticationPending;
        output.response = Ok(Self::transaction_response(
            data.connector_request_reference_id.clone(),
            Some(serde_json::json!({ "code_url": response.code_url })),
        ));
        Ok(output)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Wechatpaycn {
    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let auth = self.auth(&req.connector_auth_type)?;
        let id = req.request.get_connector_transaction_id()?;
        let path = format!(
            "/v3/pay/transactions/out-trade-no/{}?mchid={}",
            urlencoding::encode(&id),
            urlencoding::encode(&auth.mch_id.expose())
        );
        Ok(Some(self.signed_request(
            &req.connector_auth_type,
            self.base_url(connectors),
            Method::Get,
            &path,
            None,
        )?))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        self.verify_response(data, &data.connector_meta_data, &res)?;
        let response: wechat::TransactionResponse = res
            .response
            .parse_struct("WechatTransactionResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&response));
        let mut output = data.clone();
        output.status = response.status();
        output.response = Ok(Self::transaction_response(
            response.transaction_id.unwrap_or(response.out_trade_no),
            None,
        ));
        Ok(output)
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Wechatpaycn {
    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let auth = self.auth(&req.connector_auth_type)?;
        let path = format!(
            "/v3/pay/transactions/out-trade-no/{}/close",
            urlencoding::encode(&req.request.connector_transaction_id)
        );
        Ok(Some(self.signed_request(
            &req.connector_auth_type,
            self.base_url(connectors),
            Method::Post,
            &path,
            Some(serde_json::json!({ "mchid": auth.mch_id.expose() })),
        )?))
    }

    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        _event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, errors::ConnectorError> {
        self.verify_response(data, &data.connector_meta_data, &res)?;
        let mut output = data.clone();
        output.status = enums::AttemptStatus::Voided;
        output.response = Ok(Self::transaction_response(
            data.request.connector_transaction_id.clone(),
            None,
        ));
        Ok(output)
    }
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Wechatpaycn {
    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let body = serde_json::json!({
            "out_trade_no": req.request.connector_transaction_id,
            "out_refund_no": req.request.refund_id,
            "reason": req.request.reason,
            "notify_url": req.request.webhook_url,
            "amount": { "refund": req.request.minor_refund_amount, "total": req.request.minor_payment_amount, "currency": "CNY" }
        });
        Ok(Some(self.signed_request(
            &req.connector_auth_type,
            self.base_url(connectors),
            Method::Post,
            "/v3/refund/domestic/refunds",
            Some(body),
        )?))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        self.verify_response(data, &data.connector_meta_data, &res)?;
        let response: wechat::RefundResponse = res
            .response
            .parse_struct("WechatRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&response));
        let mut output = data.clone();
        let refund_status = response.status();
        output.response = Ok(RefundsResponseData {
            connector_refund_id: response.refund_id.unwrap_or(response.out_refund_no),
            refund_status,
        });
        Ok(output)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Wechatpaycn {
    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let refund_id = req
            .request
            .connector_refund_id
            .clone()
            .unwrap_or_else(|| req.request.refund_id.clone());
        let path = format!(
            "/v3/refund/domestic/refunds/{}",
            urlencoding::encode(&refund_id)
        );
        Ok(Some(self.signed_request(
            &req.connector_auth_type,
            self.base_url(connectors),
            Method::Get,
            &path,
            None,
        )?))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        self.verify_response(data, &data.connector_meta_data, &res)?;
        let response: wechat::RefundResponse = res
            .response
            .parse_struct("WechatRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&response));
        let mut output = data.clone();
        let refund_status = response.status();
        output.response = Ok(RefundsResponseData {
            connector_refund_id: response.refund_id.unwrap_or(response.out_refund_no),
            refund_status,
        });
        Ok(output)
    }
}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Wechatpaycn {
    async fn verify_webhook_source(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        merchant_id: &common_utils::id_type::MerchantId,
        connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        _connector_account_details: crypto::Encryptable<Secret<serde_json::Value>>,
        connector_name: &str,
    ) -> CustomResult<bool, errors::ConnectorError> {
        let secrets = self
            .get_webhook_source_verification_merchant_secret(
                merchant_id,
                connector_name,
                connector_webhook_details,
            )
            .await?;
        let public_key = secrets
            .additional_secret
            .ok_or(errors::ConnectorError::WebhookVerificationSecretNotFound)?;
        let header = |name: &'static str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .ok_or(errors::ConnectorError::WebhookSignatureNotFound)
        };
        let timestamp = header("Wechatpay-Timestamp")?;
        let timestamp_value = timestamp
            .parse::<i64>()
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        if (chrono::Utc::now().timestamp() - timestamp_value).abs() > 300 {
            return Ok(false);
        }
        let nonce = header("Wechatpay-Nonce")?;
        let signature = header("Wechatpay-Signature")?;
        let body = std::str::from_utf8(request.body)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        Ok(wechat::verify_signature(
            &public_key,
            &format!("{timestamp}\n{nonce}\n{body}\n"),
            signature,
        ))
    }

    async fn decode_webhook_body(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        merchant_id: &common_utils::id_type::MerchantId,
        connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        connector_name: &str,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let secrets = self
            .get_webhook_source_verification_merchant_secret(
                merchant_id,
                connector_name,
                connector_webhook_details,
            )
            .await?;
        let envelope: wechat::NotifyEnvelope = request
            .body
            .parse_struct("WechatNotifyEnvelope")
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
        serde_json::to_vec(&wechat::decrypt_notification(
            &secrets.secret,
            &envelope.resource,
        )?)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let notification: wechat::DecodedNotification = request
            .body
            .parse_struct("WechatDecodedNotification")
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        Ok(match notification {
            wechat::DecodedNotification::Payment(transaction) => {
                api_models::webhooks::ObjectReferenceId::PaymentId(
                    api_models::payments::PaymentIdType::PaymentAttemptId(transaction.out_trade_no),
                )
            }
            wechat::DecodedNotification::Refund(refund) => {
                api_models::webhooks::ObjectReferenceId::RefundId(
                    api_models::webhooks::RefundIdType::RefundId(refund.out_refund_no),
                )
            }
        })
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        let notification: wechat::DecodedNotification = request
            .body
            .parse_struct("WechatDecodedNotification")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        Ok(match notification {
            wechat::DecodedNotification::Payment(transaction) => {
                match transaction.trade_state.as_str() {
                    "SUCCESS" => api_models::webhooks::IncomingWebhookEvent::PaymentIntentSuccess,
                    "NOTPAY" | "USERPAYING" => {
                        api_models::webhooks::IncomingWebhookEvent::PaymentIntentProcessing
                    }
                    "CLOSED" | "REVOKED" | "PAYERROR" => {
                        api_models::webhooks::IncomingWebhookEvent::PaymentIntentFailure
                    }
                    _ => api_models::webhooks::IncomingWebhookEvent::EventNotSupported,
                }
            }
            wechat::DecodedNotification::Refund(refund) => match refund.status.as_str() {
                "SUCCESS" => api_models::webhooks::IncomingWebhookEvent::RefundSuccess,
                "CLOSED" | "ABNORMAL" => api_models::webhooks::IncomingWebhookEvent::RefundFailure,
                _ => api_models::webhooks::IncomingWebhookEvent::EventNotSupported,
            },
        })
    }

    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        let notification: wechat::DecodedNotification = request
            .body
            .parse_struct("WechatDecodedNotification")
            .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
        Ok(Box::new(notification))
    }

    fn get_webhook_api_response(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _error_kind: Option<webhooks::IncomingWebhookFlowError>,
        _connector_authentication_type: Option<crypto::Encryptable<Secret<serde_json::Value>>>,
    ) -> CustomResult<WebhookResponse<serde_json::Value>, errors::ConnectorError> {
        Ok(WebhookResponse::StatusOk)
    }
}

static SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(SupportedPaymentMethods::new);
static CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "WeChat Pay China",
    description: "Direct WeChat Pay API v3 Native payments",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Live,
};
static WEBHOOK_FLOWS: [enums::EventClass; 2] =
    [enums::EventClass::Payments, enums::EventClass::Refunds];

impl ConnectorSpecifications for Wechatpaycn {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&CONNECTOR_INFO)
    }
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*SUPPORTED_PAYMENT_METHODS)
    }
    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&WEBHOOK_FLOWS)
    }
}
