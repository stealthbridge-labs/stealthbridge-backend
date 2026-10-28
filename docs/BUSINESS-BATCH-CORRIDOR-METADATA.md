# Bounded public business batch route lookups

GET /v1/corridors/batch?ids=uuid1,uuid2 reads one to eight distinct, canonical-lowercase public corridor identifiers. The query and response contain only operator-configured public metadata, not user names, money, recipients, balances, fees or private policies.

The database query uses a bound UUID array. It returns enabled rows only. A missing or disabled route is reported explicitly in missing_ids, preserving the caller's original order, while all_configured reflects **metadata coverage only**. It is NEVER payment availability or legal/issuer/privacy proof; all financial flags remain false.

Malformed, repeated, uppercase, empty or oversized identifiers are rejected before database access (HTTP 400). An unavailable database returns 503; the server does not invent routes. Response is no-store and uses the existing read limiter. There are no POST actions.

Frontend batch drafts are kept in browser memory, validated locally, and submit ONLY these public UUIDs to this API. This API should not be used as evidence of proof verification, payout availability or ready-for-settlement batch.
