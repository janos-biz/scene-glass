# ADR 0001: Local-authority MVP

- **Status:** Accepted
- **Date:** 2026-07-16

## Decision

Scene Glass runs as a Node.js 24, strict TypeScript, pnpm workspace application. The local server uses Fastify 5 and binds directly to literal `127.0.0.1`; it is not a network service and does not bind to a wildcard address.

The browser client is framework-neutral and is hosted by exact Vue 3/Vite, React/Vite SPA, and canonical static HTML integrations. A host injects the active project's browser-visible local capability from its environment at startup. The integration is fail-open: unavailable Scene Glass functionality does not prevent the host page from operating.

The package boundaries are:

- `@scene-glass/contracts` owns validated configuration, wire, scalar, limit, and persisted-data contracts. It has no transport or filesystem authority.
- `@scene-glass/core` owns framework-neutral page identity, screen-review, and replay behavior.
- `@scene-glass/server` owns Fastify transport, platform probing, authentication/session handling, the static registry, and filesystem adapters.
- `@scene-glass/browser-client` owns the browser loader and common client behavior. Vue, React, and static HTML hosts supply only their host-specific lifecycle and provisioning integration.

A project registry is a version-1 host configuration plus its exact sibling credential-authority registry and environment snapshot, validated completely before the server binds. Config stores a `tokenEnv` name; the authority registry stores only the approved credential path and stable device/inode identity. Neither stores a raw token or token-derived digest. Config, token, and effective-limit changes take effect only after the coordinated server and host restart/rebuild/re-render/redeploy needed to deliver a fresh document.

Repository-local `scripts/setup`, `scripts/start`, and `scripts/uninstall` delegate to one typed onboarding engine. Setup resolves configuration using explicit supplied path, `SCENE_GLASS_CONFIG_PATH`, then `~/.scg/config.json`; previews secret-redacted changes before approval; and publishes an active manifest only after configuration plus selected authority-registry mutation under one shared config-home lock, WAL durability, and live diagnostics succeed. Start validates the complete immutable config/authority bijection before binding MCP in the foreground. Uninstall is provenance-first, reverses only setup-owned selected entries and artifacts, and preserves the checkout, annotations, adopted credentials, unrelated registry projects, and unrelated edits.

Every actual request is authorized in this order: exact document `Origin`, credential, project/session, then the opaque authorized root. Authentication happens before any root selection or filesystem work. CORS is limited to the configured exact HTTP(S) origins; preflight applies only the origin policy needed to permit an allowed actual request.

`.scg` is the sole annotation authority. Per-page data is stored below `.scg/annotations` and committed atomically. Each page retains the exact result of its latest 32 successful mutations. The count is a non-overridable PageFile v1 semantic constant: record 33 may evict only record 1 after the new complete candidate fits all effective byte limits. Lower byte limits never authorize early replay eviction; a candidate that cannot fit fails before write with `SCG_LIMIT_FILE`.

Built-in resource ceilings are absolute maxima. Global and project configuration may lower only the named supported limits, with the effective value being the minimum of the built-in, global, and project values that apply. A replay-record-count key is invalid configuration and rejects startup with `SCG_CONFIG_LIMIT_INVALID` before bind.

The supported operating-system posture is macOS first. macOS supported-filesystem evidence is release authority; Linux is secondary conformance/smoke coverage. Windows is unsupported and fails before bind with `SCG_PLATFORM_UNSUPPORTED`. Browser verification is Chromium full coverage, Firefox navigation/CORS smoke coverage, and WebKit non-gate coverage. These are support and verification scopes, not user-agent runtime blocks.

## Drivers

1. A browser at a project document origin must safely reach a local loopback service without granting any caller arbitrary root or filesystem access.
2. Local annotation data must remain authoritative, recoverable, and idempotent across restart and commit uncertainty.
3. The MVP needs one browser contract that works in Vue, React, and static HTML while remaining explicit about macOS durability and browser support evidence.
4. Operators need bounded resource use and secret provisioning that is inspectable without placing a secret in configuration, source, or logs.
5. Onboarding and removal must be repeatable without heuristic cleanup, whole-file overwrite, or deletion of user-owned project data.

## Alternatives

### A. Node.js 24, strict TypeScript, pnpm, and Fastify 5

Chosen. This keeps the server and browser integration in one language, uses the workspace's validated shared contracts, and supports the direct loopback HTTP contract.

### B. Rust/Axum server with a TypeScript browser client

Rejected for this MVP. It would introduce a second implementation language and duplicated contract/build verification without improving the defined local-authority contract.

### C. Fixed same-origin bridge

Rejected. It replaces the approved direct `127.0.0.1` exact-Origin integration contract with a different deployment boundary.

### D. Configurable or byte-driven replay-window size

Rejected. It would turn an idempotency semantic into an operator-controlled resource setting and permit replay behavior to vary by configuration. Bytes remain lower-only safety budgets; the replay count remains exactly 32.

### E. Shell-first installer with heuristic cleanup

Rejected. Shell parsing and path-based deletion cannot preserve the required typed preview, no-follow identity checks, WAL recovery, exact owned-hunk restoration, or directional credential deletion boundary.

## Why chosen

Option A gives the smallest explicit boundary that can be verified end to end: literal loopback binding, exact Origin allowlisting, credential validation before root resolution, and a host-provisioned local capability. The package split keeps validation and domain semantics independent of Fastify and of either browser host.

The static registry and environment snapshot prevent partial activation and make rotation deliberate. `.scg` ownership, atomic replacement, and exact replay results make local data behavior truthful rather than silently resetting, truncating, or deduplicating by approximation. macOS-first evidence avoids claiming cross-platform filesystem guarantees that have not been established.

The typed onboarding engine makes installation and removal part of the same authority model as runtime startup. Secretless manifests identify setup-owned files and hunks; raw credentials remain in host-owned sources; a terminal receipt makes repeated uninstall deterministic instead of rediscovering paths.

## Consequences

- Each configured origin and project identity is unique in the registry. Invalid config, invalid limits, missing or weak secret material, or invalid replay-count configuration rejects the whole startup before bind; there is no partial registry.
- The normal token is an opaque, high-entropy, host-owned environment secret. It is browser-visible only through active host provisioning and is absent from config, repository content, `.scg`, and diagnostic output. There is no normal-token endpoint or dual-token grace period.
- Rotation is a maintenance transaction: update the host secret source, restart the server, restart/rebuild/re-render/redeploy the browser host, and load a fresh document. Old documents receive the allowed-Origin access failure and do not retry with the stale token.
- Lower byte limits can reject an otherwise valid mutation. They do not shorten a retained replay window; failed candidate mutations leave the revision, annotations, replay ledger, and page file unchanged.
- The server does not dynamically reload or mutate the registry. The browser, API request content, and `.scg` files cannot raise a limit.
- Windows is not a degraded mode. Unsupported platforms or filesystems fail before bind rather than serving without the required local durability guarantees.
- SQLite is not an MVP annotation store. The only reserved seam is a future metadata adapter; `.scg` remains the annotation authority and any SQLite introduction requires a separate ADR with migration, rollback, recovery, and concurrency handling.
- Setup owns only its recorded config record, descriptors, helpers, managed cache, and setup-created credential source. The Scene Glass checkout, `<project-root>/.scg/annotations`, adopted credentials, and unrelated host edits remain user-owned.
- A provenance mismatch or recovery-required WAL blocks uninstall rather than authorizing broader deletion. The setup-created selected credential is deleted only after the fsynced irreversible uninstall decision.

## Triggers and follow-ups

A new ADR is required before any of the following changes:

- dynamic runtime registry reload, uncoordinated registry mutation, or configuration import outside the typed onboarding transaction;
- a SQLite metadata rollout;
- token grace periods or a token bootstrap endpoint;
- Windows support or a broader filesystem-support claim;
- changing PageFile replay semantics, including configurable, journaled, or unbounded replay;
- a threat model that must defend against a same-user adversarial filesystem actor beyond the trusted-local-owner model.
