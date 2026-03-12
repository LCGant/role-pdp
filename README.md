# PDP Service

[Leia em Portugues](README.pt-BR.md) | [Project root](../../README.md)

`role-pdp` is the centralized Policy Decision Point. It answers whether a subject may perform an action on a resource under the current context.

## Core scope

- centralized authorization decisions
- RBAC and tenant-aware policy evaluation
- ownership-aware decisions
- step-up and re-auth obligations
- admin APIs for policy and cache operations
- decision audit fanout to `audit`

## Design intent

The PDP is internal infrastructure. It should be called only by trusted services, not by public clients.

It is intentionally separate from authentication:

- `auth` proves who the user is and what session state exists
- `pdp` decides whether the action is allowed
- `pep` is the enforcement client that connects both sides

## Status

The PDP is already useful for real systems and fits a larger multi-service application model, including social-style products. It is still a base platform, not a complete policy control plane. Versioned policy workflows, richer policy tooling, and more advanced distributed invalidation are future work.

