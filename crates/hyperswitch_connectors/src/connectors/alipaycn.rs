pub mod transformers;

use std::sync::LazyLock;

use common_enums::enums;
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::BytesExt,
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    api::WebhookResponse,
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
        ConnectorInfo, PaymentsResponseData, RedirectForm, RefundsResponseData,
        SupportedPaymentMethods,
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
    types::{self, Response},
    webhooks,
};
use hyperswitch_masking::Secret;

use self::transformers as alipay;
use crate::utils::{self, PaymentsSyncRequestData};

#[derive(Clone)]
pub struct Alipaycn {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Alipaycn {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }

    fn auth(
        &self,
        auth: &ConnectorAuthType,
    ) -> CustomResult<alipay::AlipaycnAuthType, errors::ConnectorError> {
        alipay::AlipaycnAuthType::try_from(auth)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)
    }

    fn signed_body(
        &self,
        auth: &ConnectorAuthType,
        method: &str,
        biz: serde_json::Value,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let auth = self.auth(auth)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(
            alipay::signed_request(&auth, method, biz, None, None)?,
        )))
    }

    fn transaction_response(
        _status: enums::AttemptStatus,
        resource_id: String,
        redirection_data: Option<RedirectForm>,
    ) -> PaymentsResponseData {
        PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(resource_id),
            redirection_data: Box::new(redirection_data),
            mandate_reference: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            network_txn_link_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            authentication_data: None,
            charges: None,
        }
    }

    fn error_response(&self, res: Response) -> ErrorResponse {
        let message = String::from_utf8_lossy(&res.response).to_string();
        ErrorResponse {
            status_code: res.status_code,
            code: "ALIPAY_ERROR".to_string(),
            message: message.clone(),
            reason: Some(message),
            attempt_status: None,
            connector_transaction_id: None,
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        }
    }

    fn verify_json_response(
        &self,
        auth: &ConnectorAuthType,
        res: &Response,
        response_field: &str,
    ) -> CustomResult<(), errors::ConnectorError> {
        let auth = self.auth(auth)?;
        if !alipay::verify_json_response(&auth, &res.response, response_field)? {
            return Err(errors::ConnectorError::ResponseHandlingFailed.into());
        }
        Ok(())
    }
}

impl api::Payment for Alipaycn {}
impl api::PaymentSession for Alipaycn {}
impl api::ConnectorAccessToken for Alipaycn {}
impl api::MandateSetup for Alipaycn {}
impl api::PaymentAuthorize for Alipaycn {}
impl api::PaymentSync for Alipaycn {}
impl api::PaymentCapture for Alipaycn {}
impl api::PaymentVoid for Alipaycn {}
impl api::Refund for Alipaycn {}
impl api::RefundExecute for Alipaycn {}
impl api::RefundSync for Alipaycn {}
impl api::PaymentToken for Alipaycn {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Alipaycn
{
}

impl ConnectorCommon for Alipaycn {
    fn id(&self) -> &'static str {
        "alipaycn"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.alipaycn.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Ok(self.error_response(res))
    }
}

impl ConnectorValidation for Alipaycn {
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

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Alipaycn {}
impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Alipaycn {}
impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>
    for Alipaycn
{
}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Alipaycn {
    fn get_headers(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        Ok(vec![(
            "Content-Type".to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.base_url(connectors).to_string())
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;
        let auth = self.auth(&req.connector_auth_type)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(
            alipay::authorize_request(&auth, req, amount)?,
        )))
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        _event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        let html = String::from_utf8(res.response.to_vec())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let mut output = data.clone();
        output.status = enums::AttemptStatus::AuthenticationPending;
        output.response = Ok(Self::transaction_response(
            output.status,
            output.connector_request_reference_id.clone(),
            Some(RedirectForm::Html { html_data: html }),
        ));
        output.status = enums::AttemptStatus::AuthenticationPending;
        Ok(output)
    }

    fn get_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Ok(self.error_response(res))
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Alipaycn {
    fn get_headers(
        &self,
        _req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        Ok(vec![(
            "Content-Type".to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }

    fn get_url(
        &self,
        _req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.base_url(connectors).to_string())
    }

    fn get_request_body(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let out_trade_no = req.request.get_connector_transaction_id()?;
        self.signed_body(
            &req.connector_auth_type,
            "alipay.trade.query",
            serde_json::json!({"out_trade_no": out_trade_no}),
        )
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsSyncType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        self.verify_json_response(
            &data.connector_auth_type,
            &res,
            "alipay_trade_query_response",
        )?;
        let envelope: alipay::QueryEnvelope = res
            .response
            .parse_struct("AlipayQueryEnvelope")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&envelope));
        let response = envelope.alipay_trade_query_response;
        let mut output = data.clone();
        output.status = response.payment_status();
        let id = response
            .trade_no
            .clone()
            .or(response.out_trade_no.clone())
            .unwrap_or_else(|| output.connector_request_reference_id.clone());
        output.response = if response.is_success() {
            Ok(Self::transaction_response(output.status, id, None))
        } else {
            Err(ErrorResponse {
                status_code: res.status_code,
                code: response.sub_code.clone().unwrap_or(response.code.clone()),
                message: response.error_message(),
                reason: response.sub_msg,
                attempt_status: Some(enums::AttemptStatus::Failure),
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            })
        };
        Ok(output)
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Alipaycn {}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Alipaycn {
    fn get_headers(
        &self,
        _req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        Ok(vec![(
            "Content-Type".to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }
    fn get_url(
        &self,
        _req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.base_url(connectors).to_string())
    }
    fn get_request_body(
        &self,
        req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        self.signed_body(
            &req.connector_auth_type,
            "alipay.trade.close",
            serde_json::json!({"out_trade_no": req.request.connector_transaction_id}),
        )
    }
    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsVoidType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsVoidType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsVoidType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }
    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, errors::ConnectorError> {
        self.verify_json_response(
            &data.connector_auth_type,
            &res,
            "alipay_trade_close_response",
        )?;
        let envelope: alipay::CloseEnvelope = res
            .response
            .parse_struct("AlipayCloseEnvelope")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&envelope));
        let response = envelope.alipay_trade_close_response;
        let mut output = data.clone();
        output.status = if response.is_success() {
            enums::AttemptStatus::Voided
        } else {
            enums::AttemptStatus::VoidFailed
        };
        output.response = if response.is_success() {
            Ok(Self::transaction_response(
                output.status,
                response
                    .trade_no
                    .or(response.out_trade_no)
                    .unwrap_or_else(|| data.request.connector_transaction_id.clone()),
                None,
            ))
        } else {
            Err(self.error_response(res))
        };
        Ok(output)
    }
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Alipaycn {
    fn get_headers(
        &self,
        _req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        Ok(vec![(
            "Content-Type".to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }
    fn get_url(
        &self,
        _req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.base_url(connectors).to_string())
    }
    fn get_request_body(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount,
            req.request.currency,
        )?;
        self.signed_body(&req.connector_auth_type, "alipay.trade.refund", serde_json::json!({"out_trade_no": req.request.connector_transaction_id, "refund_amount": amount, "out_request_no": req.request.refund_id}))
    }
    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::RefundExecuteType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundExecuteType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::RefundExecuteType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }
    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        self.verify_json_response(
            &data.connector_auth_type,
            &res,
            "alipay_trade_refund_response",
        )?;
        let envelope: alipay::RefundEnvelope = res
            .response
            .parse_struct("AlipayRefundEnvelope")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&envelope));
        let response = envelope.alipay_trade_refund_response;
        let mut output = data.clone();
        output.response = if response.is_success() {
            Ok(RefundsResponseData {
                connector_refund_id: data.request.refund_id.clone(),
                refund_status: enums::RefundStatus::Success,
            })
        } else {
            Err(ErrorResponse {
                status_code: res.status_code,
                code: response.sub_code.clone().unwrap_or(response.code.clone()),
                message: response.error_message(),
                reason: response.sub_msg,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            })
        };
        Ok(output)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Alipaycn {
    fn get_headers(
        &self,
        _req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        Ok(vec![(
            "Content-Type".to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }
    fn get_url(
        &self,
        _req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.base_url(connectors).to_string())
    }
    fn get_request_body(
        &self,
        req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        self.signed_body(&req.connector_auth_type, "alipay.trade.fastpay.refund.query", serde_json::json!({"out_trade_no": req.request.connector_transaction_id, "out_request_no": req.request.connector_refund_id.clone().unwrap_or_else(|| req.request.refund_id.clone())}))
    }
    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                .set_body(types::RefundSyncType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }
    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        self.verify_json_response(
            &data.connector_auth_type,
            &res,
            "alipay_trade_fastpay_refund_query_response",
        )?;
        let envelope: alipay::RefundQueryEnvelope = res
            .response
            .parse_struct("AlipayRefundQueryEnvelope")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&envelope));
        let response = envelope.alipay_trade_fastpay_refund_query_response;
        let mut output = data.clone();
        output.response = if response.is_success() {
            Ok(RefundsResponseData {
                connector_refund_id: data
                    .request
                    .connector_refund_id
                    .clone()
                    .unwrap_or_else(|| data.request.refund_id.clone()),
                refund_status: if response.refund_fee.is_some() {
                    enums::RefundStatus::Success
                } else {
                    enums::RefundStatus::Pending
                },
            })
        } else {
            Err(ErrorResponse {
                status_code: res.status_code,
                code: response.sub_code.clone().unwrap_or(response.code.clone()),
                message: response.error_message(),
                reason: response.sub_msg,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            })
        };
        Ok(output)
    }
}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Alipaycn {
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
            .await
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        let (webhook, fields) = alipay::parse_webhook(request.body)?;
        let public_key = String::from_utf8(secrets.secret)
            .change_context(errors::ConnectorError::WebhookVerificationSecretInvalid)?;
        Ok(alipay::verify_signature(
            &public_key,
            &alipay::sign_content(&fields, true),
            &webhook.sign,
        ))
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let (webhook, _) = alipay::parse_webhook(request.body)?;
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::PaymentAttemptId(webhook.out_trade_no),
        ))
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        let (webhook, _) = alipay::parse_webhook(request.body)?;
        Ok(match webhook.trade_status.as_str() {
            "TRADE_SUCCESS" | "TRADE_FINISHED" => {
                api_models::webhooks::IncomingWebhookEvent::PaymentIntentSuccess
            }
            "TRADE_CLOSED" => api_models::webhooks::IncomingWebhookEvent::PaymentIntentFailure,
            "WAIT_BUYER_PAY" => api_models::webhooks::IncomingWebhookEvent::PaymentIntentProcessing,
            _ => api_models::webhooks::IncomingWebhookEvent::EventNotSupported,
        })
    }

    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        let (webhook, _) = alipay::parse_webhook(request.body)?;
        Ok(Box::new(webhook))
    }

    fn get_webhook_api_response(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _error_kind: Option<webhooks::IncomingWebhookFlowError>,
        _connector_authentication_type: Option<crypto::Encryptable<Secret<serde_json::Value>>>,
    ) -> CustomResult<WebhookResponse<serde_json::Value>, errors::ConnectorError> {
        Ok(WebhookResponse::TextPlain("success".to_string()))
    }
}

static SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(SupportedPaymentMethods::new);
static CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Alipay China",
    description: "Direct Alipay mainland page and WAP payments",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Live,
};
static WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];

impl ConnectorSpecifications for Alipaycn {
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
