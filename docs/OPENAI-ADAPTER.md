# OpenAI model inventory adapter

`openai.models.list@1.0.0` implements only `GET /v1/models` against
`https://api.openai.com`. The task resource is an exact configured OpenAI
project ID. The caller cannot supply a URL, method, header or request body.

The runtime first checks the account, project, environment, consumed task
execution ID and canonical request binding. It then requests a maximum
five-minute capability from the provider credential service. The response must
echo the complete binding and be current; substitution, expiry and replay fail
closed. Plaintext provider tokens are not accepted in Broker configuration.

Only model IDs are returned. Ownership and all other upstream fields are
discarded. Responses are size- and count-bounded, redirects are denied, TLS is
verified against the fixed hostname, and DNS answers are pinned after public-IP
validation.

OpenAI workload identity federation is the preferred production authority. It
maps a short-lived external workload identity to a dedicated API Platform
project service account and returns a short-lived access token. A scoped,
expiring project service-account API key is the fallback; ChatGPT login
credentials are never accepted as API credentials.

The adapter and protocol tests are local deterministic evidence only. The
provider remains `contract_required` until a real isolated OpenAI project proves
token exchange, least privilege, revocation, error redaction and the fixed
model-list request.

Official references checked on 2026-09-11:

- [List models](https://developers.openai.com/api/reference/resources/models/methods/list)
- [Workload identity federation](https://developers.openai.com/api/docs/guides/workload-identity-federation)
