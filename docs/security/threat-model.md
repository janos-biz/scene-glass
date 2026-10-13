# Scene Glass MVP threat model

## Scope and trust statement

Scene Glass is a local-authority service, not a multi-user or network-facing service. It binds only to literal `127.0.0.1` and serves configured project documents that have exact HTTP(S) Origins. The trusted local owner controls the host configuration, environment, project roots, supported local filesystem, and the browser host that provisions the local capability.

A browser-visible local token is a capability, not protection from code that already executes in an allowed document. In particular, same-origin XSS is inside the authorized browser boundary and can exercise the victim project's Scene Glass permissions. Scene Glass limits the capability to the configured project/root/session; it does not make a compromised allowed origin trustworthy.

## Assets

| Asset                                                      | Required property                                                                                                        |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Normal project token and its derived verifier state        | High-entropy host-owned capability; never persisted in configuration, `.scg`, repository content, or diagnostic output.  |
| Project registry, root binding, and exact Origin allowlist | A request cannot select another project's root or use an unconfigured Origin.                                            |
| `.scg/annotations` PageFile data                           | The sole annotation authority; data is not silently reset, dual-written, or redirected outside the authorized root.      |
| Mutation revision and replay result window                 | Latest 32 successful mutations per page have their exact persisted result; failed candidates do not alter the window.    |
| Browser host availability                                  | A Scene Glass failure does not take down the Vue 3 or static HTML host.                                                  |
| Configuration and effective limits                         | Validated static startup snapshot; no caller can raise a built-in maximum or dynamically activate changed configuration. |
| Diagnostic capability                                      | Separate audience, 60-second, single-run, memory-only capability limited to diagnostics; it cannot mutate `.scg`.        |

## Actors

| Actor                                                      | Capability and trust level                                                                                                                                                                 |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Trusted local owner                                        | Controls the machine, host configuration and environment, project roots, and browser host. This actor is trusted to protect local secrets and choose safe content.                         |
| Allowed document                                           | May send requests from a configured exact Origin and receives the project capability through its host. It is trusted only to the extent that its scripts and dependencies are free of XSS. |
| Same-origin XSS or malicious script in an allowed document | Can use the browser-visible capability and make authorized requests for that document's project. It is a material residual risk.                                                           |
| Other website or remote attacker                           | Can induce browser requests but lacks an allowed exact Origin and local capability. It must not gain CORS access or root selection.                                                        |
| Unrelated local process                                    | Can reach loopback but has no browser Origin/capability by default. It must not receive project data or filesystem authority.                                                              |
| Same-user filesystem adversary                             | May attempt path swaps or filesystem manipulation. This is outside the trusted-local-owner model except where runtime rechecks can detect it.                                              |

## Trust boundaries

1. **Browser document to local server.** The browser crosses from an exact configured HTTP(S) Origin to `127.0.0.1`. Origin is necessary but not sufficient: a valid credential is also required.
2. **Capability to project/session.** The capability identifies a configured project and session; it is not a general local-server credential.
3. **Project/session to filesystem root.** Only after exact Origin and credential validation may the server resolve the opaque authorized root. Authentication happens before root selection.
4. **Filesystem root to `.scg` authority.** The server owns the `.scg/annotations` location beneath the authorized root. Page identity and paths are validated so request input cannot choose arbitrary files.
5. **Host configuration/environment to browser provisioning.** Version-1 configuration carries only the environment-variable name. The host and server consume the same startup secret source; the raw secret crosses into the browser only as the active local capability.
6. **Process lifetime to persistent state.** Atomic replacement and exact replay records bridge process failure and retry. A write result is not claimed complete when persistence is indeterminate.

## Mitigations

### Transport, Origin, and authentication

- The server binds to literal `127.0.0.1`, not a wildcard interface.
- Each allowed Origin is an exact serialized `http` or `https` origin: scheme, host, and port only, with no path, query, fragment, credentials, or wildcard matching. Origins are unique across projects.
- CORS is narrow. Unauthenticated preflight evaluates only Origin policy; every actual request follows exact Origin, credential, project/session, and authorized-root validation in that order.
- The normal token is an opaque host environment secret with at least 256 bits of entropy. It is absent from configuration and logs. No endpoint issues a normal token, and rotation has no dual-token grace period.
- The browser host treats server absence and CORS-obscured denial as unavailable without blocking the host application. An allowed-Origin `401`/access error is not retried with a stale capability.

### Configuration and resource boundaries

- The version-1 configuration and referenced environment are validated as a whole before bind. Duplicate project IDs, canonical roots, token digests, or Origins; unknown fields; weak or absent token material; invalid limits; and invalid schema versions reject the whole startup.
- The registry is immutable for the process lifetime. There is no watcher, signal reload, admin mutation surface, or client-side configuration activation.
- Built-in resource ceilings are absolute maxima. Global and project overrides may only lower explicitly named limits. Browser input, `.scg`, and environment content cannot raise a limit.
- `replayRecordCount` and every replay-record/window-count alias are rejected with `SCG_CONFIG_LIMIT_INVALID`; the PageFile v1 replay count is exactly 32.

### Storage, integrity, and replay

- `.scg` remains the annotation authority. Page files use validated page identity and schema, and commits use same-directory atomic replacement with filesystem durability checks.
- The server stages the complete candidate mutation, exact result, 32-record replay ledger, and page bytes under the project write lock before changing the aggregate or filesystem. If an effective byte limit cannot fit the candidate, it returns `SCG_LIMIT_FILE` with no write, revision change, replay eviction, or temporary commit.
- On commit uncertainty, visible old and visible new outcomes are distinguished through strict read-back. Other outcomes are integrity failures, not success.
- Detectable root replacement produces `SCG_ROOT_CHANGED` and a server-wide write stop. Corrupt, noncanonical, or integrity-invalid data is not silently initialized or reset.

### Platform and diagnostic containment

- The server binds only after the supported-platform/filesystem probe succeeds. Windows, unknown platforms, and nonconforming filesystems fail before bind; Windows reports `SCG_PLATFORM_UNSUPPORTED`.
- The diagnostic capability is separately scoped, memory-only, single-run, and limited to 60 seconds. It permits only diagnostics operations and cannot modify `.scg`.
- Browser/API-visible errors are redacted to stable status and contract code where applicable. They do not disclose raw token values, configuration values, filesystem paths, root identity, or other-project information.

## Residual risk

- **Same-origin XSS:** an attacker executing JavaScript in an allowed document can use that document's browser-visible capability and modify its authorized project. Origin checks, CORS, and token checks cannot distinguish that script from the host application. The local owner must treat XSS prevention, dependency integrity, and host deployment security as prerequisites.
- **Trusted local owner compromise:** a user or process with the owner's operating-system authority can inspect process/environment state, alter host configuration, or modify local files. This model does not attempt to protect a secret from its host owner.
- **Same-user filesystem race:** root rechecks detect a path swap when observed, but a microscopic race against a same-user adversary is residual. The product does not claim descriptor-relative filesystem isolation beyond the supported probe and checks.
- **Browser-visible capability exposure:** the capability must be present in the running allowed document. Compromised extensions, developer tooling, or page code with equivalent browser authority may expose it.
- **Availability:** local service failure, browser policy behavior, or a low configured byte ceiling can make Scene Glass unavailable or reject a mutation. Fail-open host behavior preserves the host page, not Scene Glass availability.

## Fail-stop conditions

The service must stop rather than weaken a boundary in these cases:

| Condition                                                                                                                             | Required behavior                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Invalid version-1 config, duplicate registry identity, missing/weak token material, invalid limit, or attempted replay-count override | Reject the entire startup before bind; do not create a partial registry. An attempted count override uses `SCG_CONFIG_LIMIT_INVALID`. |
| Windows, unknown platform, or unsupported filesystem probe                                                                            | Fail before bind; Windows uses `SCG_PLATFORM_UNSUPPORTED`.                                                                            |
| Disallowed/malformed Origin or missing/invalid capability                                                                             | Deny before root selection or filesystem access.                                                                                      |
| Detectable root swap                                                                                                                  | Emit `SCG_ROOT_CHANGED` and stop all server writes.                                                                                   |
| Corrupt/noncanonical PageFile or an integrity read-back result that is neither exact old nor exact new                                | Quarantine or stop affected writes; never reset the data or report success.                                                           |
| Candidate replay/result/ledger/page bytes exceed an effective lower-only limit                                                        | Return `SCG_LIMIT_FILE` before mutation; leave revision, annotations, replay records, and page bytes unchanged.                       |
| Persistence outcome remains indeterminate                                                                                             | Do not claim completion. Use strict read-back and exact retry/replay semantics only after determining visible state.                  |
