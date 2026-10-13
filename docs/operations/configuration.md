# Configuration

## Lifecycle selection and local state

The repo-local lifecycle stores its default schema-v1 project configuration at `~/.scg/config.json`. The sibling `~/.scg/credential-authorities.v1.json` stores the secretless path and stable device/inode authority for each configured credential. Where the lifecycle is supplied an explicit CLI configuration path, it takes precedence over `SCENE_GLASS_CONFIG_PATH`, which takes precedence over that home default. The public wrappers accept no arguments: invoke the same canonical Scene Glass checkout's `scripts/setup`, `scripts/start`, or `scripts/uninstall` from the supported host project's root, and use `SCENE_GLASS_CONFIG_PATH` or the default to select configuration.

Setup previews this selection and every planned mutation before it requires approval. It serializes configuration and authority-registry work through the shared config-home `onboarding.lock`, while keeping each host's secretless ownership provenance under `<project-root>/.scg/onboarding` (active manifest, WAL, and terminal receipt). This state is distinct from `<project-root>/.scg/runtime`, which holds setup-owned host descriptor/helper files, and from `<project-root>/.scg/annotations`, which remains authoritative project data and is never lifecycle-managed.

Uninstall reads provenance first. It restores or removes only the selected, still-owned project configuration and credential-authority entries plus managed host artifacts; unrelated configuration/registry entries, checkout contents, annotations, adopted credentials, and unrelated edits remain. Removing the last selected authority retains a canonical empty registry. A provenance conflict or recovery-required WAL performs no target mutation—preserve the reported files and lifecycle state while reconciling the conflict.
A legacy active manifest under `<checkout>/.scg/onboarding` is still selected when it proves ownership of the invoked host root; it is not silently migrated. New setups use per-host state, which allows independent setup/uninstall provenance for multiple projects sharing the same checkout and configuration home.

## Version-1 startup snapshot

Scene Glass reads one version-1 host configuration and its sibling canonical credential-authority registry at process startup. The validated result is an immutable project registry, authority set, and effective-limit snapshot. The server validates the complete configuration, exact config/authority project bijection, and required token material before it binds `127.0.0.1`; it never partially activates a valid subset.

`config.json` contains **environment-variable names only**. It does not contain a token value, token digest, connection string, or credential-file path. `credential-authorities.v1.json` contains the canonical credential path plus device/inode identity, but never the token or a token-derived digest. The host environment supplies each named normal token as a high-entropy opaque secret (at least 256 bits of entropy). Do not place a token value in JSON, source control, `.scg`, shell history, logs, or support tickets.

```json
{
  "schemaVersion": 1,
  "globalLimits": {
    "httpBodyBytes": 524288,
    "concurrentRequestsGlobal": 32
  },
  "projects": [
    {
      "projectId": "catalog",
      "root": "/srv/scene-glass/catalog",
      "allowedOrigins": ["https://catalog.example.test"],
      "tokenEnv": "SCENE_GLASS_CATALOG_TOKEN",
      "framework": "vue3",
      "limits": {
        "memoBytes": 8192,
        "pageFileBytes": 4194304,
        "replayResultBytes": 32768,
        "normalSessionsPerProject": 16
      }
    },
    {
      "projectId": "docs",
      "root": "/srv/scene-glass/docs",
      "allowedOrigins": ["https://docs.example.test"],
      "tokenEnv": "SCENE_GLASS_DOCS_TOKEN",
      "framework": "html",
      "limits": {
        "annotationsPerPage": 500,
        "replayLedgerBytes": 1048576
      }
    }
  ]
}
```

The example deliberately shows token environment names, not values. The server and the active Vue 3/Vite, React/Vite, or canonical static HTML host consume the same named secret source during their startup/provisioning lifecycle. The browser receives a project-scoped, browser-visible local capability only through its active host integration.

The authority registry is setup-owned and canonically serialized beside the configuration:

```json
{
  "schemaVersion": 1,
  "projects": [
    {
      "projectId": "catalog",
      "tokenEnv": "SCENE_GLASS_CATALOG_TOKEN",
      "canonicalRoot": "/srv/scene-glass/catalog",
      "credentialPath": "/srv/scene-glass/catalog/.scg/runtime/host.env",
      "device": "16777233",
      "inode": "4890123"
    }
  ]
}
```

Entries are sorted by project ID and must match `config.json` exactly on project ID, token environment, and canonical root. Paths and identities are local authority metadata, not secrets, but they remain excluded from public errors and support output. Setup and uninstall change only their selected entry and preserve every unrelated valid entry.

## Schema and registry rules

`schemaVersion` must be the number `1`. The only top-level fields are:

- `schemaVersion`
- optional `globalLimits`
- `projects`

Each project has these fields:

| Field            | Requirement                                                                                                                                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `projectId`      | Unique, 1–128 lowercase ASCII letters, digits, `_`, or `-`; starts with a letter or digit.                                                                                                                |
| `root`           | Non-blank, well-formed path string. The runtime validates the authorized root before use.                                                                                                                 |
| `allowedOrigins` | Non-empty array of unique, exact serialized HTTP(S) origins. Origin values contain only scheme, host, and port—no path, query, fragment, user info, or wildcard. An Origin cannot appear in two projects. |
| `tokenEnv`       | Name of the environment variable holding the project normal token. It is a name, not the token.                                                                                                           |
| `limits`         | Optional project-level lower-only limit overrides.                                                                                                                                                        |
| `framework`      | Optional `vue3`, `react`, or `html` host label. The lifecycle records the detected supported host explicitly.                                                                                             |

### Lifecycle Vite Origin snapshot

For projects managed by the public lifecycle, `allowedOrigins` remains durable setup provenance. Before `scripts/start` binds, it re-reads every registered Vite project's bounded `package.json` and `vite.config.ts`, requires a statically attestable loopback HTTP declaration with a deterministic port (accepted literal CLI/config value or default `5173`) and strictness resolved literally true through bare CLI `--strictPort` or `server.strictPort: true`, and derives the exact `127.0.0.1`/`localhost` pair. The complete replacement is applied only to that process's immutable startup snapshot; config, registry, manifest, and selected-project host descriptors are not rewritten.

The operation is all-or-nothing across the configuration home. An invalid declaration, disallowed port (`80` or Scene Glass's `4175`), duplicate Origin pair, persisted-baseline mismatch, or input mutation during finalization fails before the one `127.0.0.1:4175` listener binds. The diagnostic reports only a closed error code and project identifier, never roots, Origins, source text, fingerprints, credential paths, or tokens. Static HTML records and non-lifecycle server construction continue to use persisted exact Origins.

Unknown fields are rejected. Project IDs, canonical roots, allowed Origins, and loaded token digests must be unique across the registry. A missing, weak, or duplicate token; an invalid root/origin; an unknown schema version; or any invalid limit rejects the entire startup before bind.

## Limits: lower only

Built-in ceilings are absolute maximums. `globalLimits` and project `limits` may supply only positive safe-integer values at or below the corresponding built-in ceiling. The effective value is the minimum of the built-in value and every applicable override:

```text
effective limit = min(built-in, configured global value when allowed, configured project value when allowed)
```

The configuration example lowers several limits: a 1 MiB built-in HTTP-body ceiling becomes 512 KiB globally; the 16 KiB memo ceiling becomes 8 KiB for `catalog`; and the 8 MiB page-file ceiling becomes 4 MiB for that project. These overrides cannot raise a ceiling, and request content, browser code, environment content, or `.scg` data cannot raise one either.

Global overrides can include global request/body controls and globally applicable resource ceilings. Project overrides cannot include global-only fields such as `httpBodyBytes`, `concurrentRequestsGlobal`, `normalSessionsGlobal`, or `diagnosticActiveRunsGlobal`.

### Exact replay is not a limit setting

PageFile v1 keeps the latest **exactly 32 successful mutation records**. `replayRecordCount` is not configurable. Neither are aliases that express replay record/window count, including `replayRecordsCount`, `replayWindowSize`, `replayWindowCount`, `replayCount`, `replayCountLimit`, `recordCount`, or `replayRecords`.

For example, this configuration is invalid and prevents startup:

```json
{
  "schemaVersion": 1,
  "projects": [
    {
      "projectId": "catalog",
      "root": "/srv/scene-glass/catalog",
      "allowedOrigins": ["https://catalog.example.test"],
      "tokenEnv": "SCENE_GLASS_CATALOG_TOKEN",
      "limits": {
        "replayRecordCount": 16
      }
    }
  ]
}
```

A replay-count key is rejected as `SCG_CONFIG_LIMIT_INVALID` before the server binds. Lower byte ceilings for page files, replay ledgers, or replay results do not shorten the retained window. If the complete candidate cannot fit, the mutation fails with `SCG_LIMIT_FILE` before write; it does not evict a retained record, change the revision, or modify the PageFile.

## Activation and rotation

Configuration, effective limits, loaded token verifier state, and lifecycle-derived Vite Origin pairs are restart-only. There is no dynamic reload, watcher, signal reload, admin API, UI mutation, listener discovery, port scan, or runtime configuration mutation path. The repo-local `setup` and `uninstall` lifecycle commands may transactionally add or remove only their owned project record while the service is stopped; they never hot-reload a running server. A public lifecycle restart may re-derive changed literal Vite declarations into the new in-memory startup snapshot without modifying persisted provenance.

To activate a changed configuration, limit, or normal token:

1. Update the host-managed configuration and/or secret source without putting a raw token in the configuration file.
2. Restart the MCP/server process so it validates a new complete snapshot before binding.
3. Restart, rebuild, re-render, or redeploy each affected Vue 3/Vite, React/Vite, or static HTML host so it provisions the new token to a fresh document.
4. Load a fresh document.

For normal-token rotation, this ordering is required: secret update, server restart, host restart/rebuild/re-render/redeploy, then fresh document load. There is no dual-token grace period and no runtime normal-token endpoint. Old documents and sessions are torn down; an old document from an allowed Origin receives the access error and does not retry with its stale capability.

## Error handling and support data

Configuration failures are fail-before-bind failures. `SCG_CONFIG_INVALID` identifies invalid version-1 configuration; `SCG_CONFIG_LIMIT_INVALID` identifies an invalid lower-only limit or attempted replay-count configuration. A candidate mutation that cannot fit effective storage limits uses `SCG_LIMIT_FILE` and is a no-write result.

Error output must be redacted. At browser/API boundaries and in support evidence, expose only the stable status and contract code needed to act on the error. Do not disclose raw token values, token digests, environment values, full configuration content, root paths, allowed-Origin lists, or other-project identity. Record secret-free operational context separately and preserve the failed configuration for the trusted local owner only.

On Windows, unknown platforms, and filesystems that do not pass the required probe, the server fails before bind rather than applying a configuration with weaker durability guarantees. Windows uses `SCG_PLATFORM_UNSUPPORTED`.
