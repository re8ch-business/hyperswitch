# RE8CH China payment connectors

This fork adds native Hyperswitch connectors for direct mainland China merchant
integrations. The connectors do not proxy through the legacy Nuclio functions.

## `alipaycn`

Supported flows:

- Alipay PC website and WAP website payment authorization
- payment status synchronization
- order close
- refund and refund status synchronization
- RSA2-verified payment webhooks

Use `wallet.alipay_redirect`. Its optional `channel` value is `page` or `wap`;
the connector defaults to `page`.

Configure `SignatureKey` as follows:

| Hyperswitch field | Alipay value |
| --- | --- |
| `api_key` | application ID |
| `key1` | Alipay public key |
| `api_secret` | application RSA private key |

The connector endpoint is `https://openapi.alipay.com/gateway.do` in production
and may be changed to the Alipay sandbox gateway in sandbox configuration.

## `wechatpaycn`

Supported flows:

- WeChat Pay API v3 Native QR authorization
- payment status synchronization
- order close
- refund and refund status synchronization
- signed and AES-256-GCM encrypted payment and refund webhooks

Use `wallet.we_chat_pay_qr` and CNY. Configure `MultiAuthKey` as follows:

| Hyperswitch field | WeChat Pay value |
| --- | --- |
| `api_key` | merchant ID |
| `key1` | application ID |
| `api_secret` | merchant API private key |
| `key2` | merchant API certificate serial number |

Connector metadata must contain `platform_public_key`, and may contain
`platform_key_id` to enforce the response-signature key identifier. Configure
the webhook verification `secret` as the 32-byte API v3 key and
`additional_secret` as the WeChat Pay platform public key.

Never commit these credentials. Store production and sandbox connector accounts
separately in the deployment's encrypted secret store.
