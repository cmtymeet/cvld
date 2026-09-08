# Independent verification providers

Research snapshot: 2026-09-08. These are candidates, not adopted providers. No signup, SMS, payment or external contact was performed. Phone checking and payment processing are independently operated services; cvld must not receive raw identity or an operator-accessible lookup handle for it.

| Candidate | Documented interface | Fit and unresolved evidence |
|---|---|---|
| [humanID](https://docs.human-id.org/web-sdk-integration-guide) | Hosted phone login; server exchange returns an application-specific pseudonymous ID | Candidate for a trusted receipt adapter. The provider need not implement cvld's credential protocol. Full production dashboard/API lookup access, application/session binding and repeat-registration lifecycle remain unverified. |
| [Human.tech / Holonym](https://docs.passport.human.tech/building-with-passport/individual-verifications/api-reference) | Phone credential/uniqueness proofs with wallet-address verification and expiry | Existing privacy-credential machinery, but public wallet linkage and supported application-scoped off-chain integration need scrutiny. No compatible cvld issuer interface is established. |
| [Taler Operations](https://www.taler-ops.ch/en/merchants.html) | Externally operated fiat digital cash and hosted merchant infrastructure | Stronger payment-privacy alignment than ordinary card checkout; current geographical limits, hosted blind-pass support, credential binding and transaction metadata remain unresolved. |

A hosted card form or SMS SDK alone does not meet the boundary when the application operator can inspect payer/phone records through its service account. cvld consumes externally checked evidence; an internal mock gate cannot establish that a compatible provider exists.

## Receipt adapters and independent checking

Independently operating the phone or payment check does not require the provider to implement AnonCreds or sign cvld's own attestation format. A cvld adapter may consume an authenticated opaque provider receipt, bind it to a pending passkey-authorized issuance operation, enforce durable subject uniqueness, and authorize credential issuance locally. The provider still owns the phone/payment interaction. A signature added by that adapter is an internal assertion, and must not be described as the provider's signature.

For an application-specific random provider subject, a proposed minimal record is a keyed, community-scoped deduplication tag associated with one stable member ID. Credential expiry and passkey rotation must preserve that association. Such a tag reduces retained identifiers; it does not establish that the provider has no underlying identity mapping, prevent a malicious adapter logging the original pseudonym, or prove that operator dashboard/support access cannot expose identity. Those are separate provider-selection requirements.

Application and session binding are mandatory. A receipt from another provider application, an unsigned browser success, or an attacker-chosen correlation value cannot authorize an arbitrary local account. Local replay protection must remain correct under concurrent completion and restart. A lost response after remote consumption requires an explicit retry or reverification path; two independent services do not share a SQLite transaction.

## humanID

The hosted Web SDK requests a login URL, then exchanges a returned token server-to-server. The documented result contains an app-specific ID and country metadata, not a phone number. This supports pseudonymous application recognition, not necessarily unlinkability from the provider's authentication session. Do not forward unneeded country data or exchange tokens into chat identity.

The [main integration guide](https://docs.human-id.org/web-sdk-integration-guide) says web integration requires provider setup; the [example guide](https://docs.human-id.org/web-sdk-integration-guide/example-web-sdk-integration) refers to console setup. Current provisioning must be verified. The adapter can perform local issuance binding, but documented callback examples alone do not establish all application/session ownership and replay guarantees it needs. Current deployed response schema and substitution behavior require validation. [Provider data and pricing claims](https://www.human-internet.org/partner-with-us) are not a substitute for examining the actual API and operator dashboard.

## Human.tech

The standard phone-status API queries a wallet address. A true result alone does not prove that the presenter controls that wallet, and a reused wallet may link activity across applications. [Credential documentation](https://docs.id.human.tech/how-it-works/credentials) describes private phone fields and scope-related cryptographic machinery; compatible production scope, proof, renewal and recovery semantics still need executable validation. No government-ID or biometric requirement is selected by this research.

## Payment credentials

GNU Taler uses blind payments and documents [merchant tokens](https://docs.taler.net/core/api-merchant.html). Its [Paivana passes](https://docs.taler.net/taler-paivana-manual.html) are time-limited access credentials, not automatic recurring charges. The concrete Swiss provider currently lists CH IBAN/+41 prerequisites on its [service page](https://www.taler-ops.ch/en/index.html). Hosted token functionality, holder binding and replay handling must be confirmed before adopting an adapter. Merchant order/amount/time information remains distinct from payer identity and still deserves minimization.

## Acceptance work

- Authenticated provider success must bind to the correct issuance request and configured policy.
- Repeated verification, recovery or expiry must not silently reset the provider's promised uniqueness scope.
- Enumerate callback, API, dashboard, export and support lookup access; a filtered response is not inability to know.
- Reject forged browser success and replay/concurrent redemption.
- Verify provider availability, exact costs and allowed integrations before any live use. No real-money spending is authorized.

The current cvld cryptographic tests use synthetic signed facts. They prove tested integration behavior, not provider independence, real-world uniqueness or deployment anonymity.
