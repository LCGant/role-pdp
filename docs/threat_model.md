# PDP Threat Model

This document focuses on the PDP trust boundary and the flows that must remain
safe.

## Assets

- policy decisions (`allow`, `reason`, `obligations`)
- RBAC bindings and admin APIs
- audit log of decisions
- internal service credentials

## Trust boundaries

1. Public clients do not talk to the PDP directly.
2. Trusted callers are internal services such as PEPs or the gateway.
3. The PDP trusts caller identity only after internal authentication
   (`X-Internal-Token` or stronger transport controls such as mTLS).

## Flow: normal authorization

1. Auth service validates the session.
2. Trusted caller builds `subject` and `resource`.
3. Trusted caller adds real request context when policy depends on it.
4. PDP evaluates RBAC, ownership, step-up, and context policies.

Security property:
- PDP must not invent policy-relevant context if the caller omitted it.

## Flow: step-up / reauth

1. Trusted caller sends `subject.aal` and `subject.auth_time`.
2. PDP returns deny with obligations when higher assurance or fresher auth is
   required.
3. Upstream service is responsible for enforcing the obligation and retrying
   with updated session state.

Security property:
- Missing or stale `auth_time` must fail closed.

## Flow: admin

1. Admin caller sends `X-Admin-Token`.
2. PDP clears caches or mutates RBAC state.

Security properties:
- Admin token is distinct from internal decision and metrics tokens.
- Admin routes stay off the public gateway.

## Flow: metrics

1. Loopback requests are allowed without token.
2. Non-loopback requests must provide `X-Metrics-Token`.

Security property:
- Metrics credentials must not grant decision or admin access.

## Main threats

- spoofed internal caller
- forged policy context
- tenant confusion
- stale or fabricated `auth_time`
- cache poisoning or stale authorization data
- admin surface exposure
- metrics exposure with over-scoped credentials

## Mitigations

- internal token or mTLS on decision routes
- admin token and metrics token separated by scope
- deny on tenant mismatch
- strict JSON decoding and body size limits
- cache clear support after admin mutations
- explicit trusted-caller requirement for request context

## Operational notes

- Compose files are for development defaults; production should isolate admin
  routes and internal decision traffic.
- Smoke tests should use auth introspection output as the canonical subject for
  PDP scenarios.
- See `../../docs/SECURITY_INVARIANTS.md` for cross-service invariants.
