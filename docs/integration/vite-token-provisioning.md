# Vite token provisioning

Use this contract for a supported Vue 3/Vite or React/Vite SPA host. The user runs the host's own Vite development server; Scene Glass only injects the loader into the host's `index.html` and runs the authenticated MCP and loader on `127.0.0.1:4175`. Scene Glass is optional to the host: loader failure, an unavailable local MCP, or `401` must not prevent the application from rendering or navigating.

## Automated onboarding and removal

From the supported Vite project root, invoke every lifecycle command through the same canonical Scene Glass checkout:

```sh
cd /path/to/your-vite-project
/path/to/scene-glass/scripts/setup
/path/to/scene-glass/scripts/start
# Later, after stopping start:
/path/to/scene-glass/scripts/uninstall
```

`setup` previews the secret-redacted configuration, credential, and host-artifact plan and requires approval before it mutates anything. `start` is parameter-free foreground startup for one MCP/loader listener on `127.0.0.1:4175`; it does not accept Vite options or daemonize. Start each host's own Vite server separately (for example, `npm run dev`). `uninstall` validates provenance before restoration or removal; it preserves the checkout, `<project-root>/.scg/annotations`, adopted credentials, and unrelated edits. A provenance conflict or recovery-required state changes no target: keep `<project-root>/.scg/onboarding` and reconcile the reported change instead of deleting lifecycle files.

This path accepts only the exact supported Vue 3/Vite or React/Vite topology. The direct `dev` script and `vite.config.ts` must be bounded, statically readable declarations that resolve to loopback HTTP and a deterministic port (an accepted literal CLI/config value or default `5173`), and strictness must resolve literally true through either the bare `--strictPort` script flag (which takes precedence) or `server.strictPort: true`. Ports `80` and `4175`, HTTPS, dynamic or ambiguous config, extra/config-hook-capable plugins, Next.js, PWA/service-worker evidence, and unsupported topology are rejected without fallback. The manual tag contract below documents the exact Vite browser provisioner; it does not broaden supported topology.

## Runtime port changes and multiple projects

Setup records the then-current exact Origin pair as durable provenance. Each `scripts/start` re-reads the bounded `package.json` and `vite.config.ts` for every Vite project registered in the selected configuration home, statically re-derives its declared port (literal CLI/config value or default `5173`), and replaces only the in-memory startup Origin pair. It does not execute Vite config, inspect a running server, scan ports, or persist the replacement. Update any explicit literal package/config declarations consistently, keep declared strictness true with bare `--strictPort` or `server.strictPort: true`, and restart Scene Glass to apply a port change.

The revalidation is atomic across the registered set: one invalid, conflicting, or changed-during-start declaration blocks the single `127.0.0.1:4175` service before listen. A successful process serves all registered projects with separate project credentials and exact per-project Origin checks. Starting a second Scene Glass process against the same active configuration is refused; stop the first process before restarting. Static HTML projects are not runtime-derived and retain their persisted Origin policy.

## Development credential environment

During setup, Scene Glass creates or adopts `<project-root>/.env.development.local`. Plain Vite automatically loads this file only in development mode. It contains exactly these newline-terminated assignments, in order:

```text
VITE_SCENE_GLASS_LOADER_URL=http://127.0.0.1:4175/scene-glass-loader.js
VITE_SCENE_GLASS_PROJECT_ID=<projectId>
VITE_SCENE_GLASS_PROJECT_TOKEN=<token>
SCENE_GLASS_HOST_TOKEN=<token>
```

The two token values in one host envelope are byte-identical. Setup creates an absent file as mode `0600` and removes only that setup-created artifact during uninstall. It adopts an existing file without writing it only when it is this exact canonical envelope for the selected project; partial, unrelated, duplicate, or mismatched content is rejected. The fixed host-envelope key remains `SCENE_GLASS_HOST_TOKEN`; the lifecycle binds each registered project to a distinct generated server `tokenEnv` name only inside the server startup environment. Setup also rejects `VITE_SCENE_GLASS_*` assignments in `.env`, `.env.local`, `.env.development`, the process environment, or any competing development environment file, because those values could override the provisioned browser values.

## Host template contract

Put this one-line asynchronous loader tag in Vite's `index.html` template:

```text
<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa"></script>
```

The `async` attribute is required. Do not wrap the loader in a framework component, await it during application startup, or replace it with a runtime token endpoint or global token function. The loader reads `data-scg-token` once and removes that attribute; host code must not copy the token elsewhere.

## Page identity

This section is the authoritative page-identity contract for every host; the [static HTML guide](./static-token-provisioning.md#page-identity) applies these same semantics to rendered documents.

By default, Scene Glass uses only `location.pathname` as the canonical page identity. Ordinary query strings and hash fragments stay excluded; the loader never infers that either is meaningful.

Configure a static identity on the loader tag with `data-scg-page-identity`. Its value must be non-empty and overrides the browser pathname, query, and hash. Configure location parts only with `data-scg-include-query` and `data-scg-include-hash`; their values must be exact lowercase `true` or `false`. Omit either attribute, or set it to `false`, to exclude that location part.

```text
<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa" data-scg-page-identity="/workspaces/42"></script>
```

```text
<script async src="%VITE_SCENE_GLASS_LOADER_URL%" data-scg-project="%VITE_SCENE_GLASS_PROJECT_ID%" data-scg-token="%VITE_SCENE_GLASS_PROJECT_TOKEN%" data-scg-navigation="spa" data-scg-include-query="true" data-scg-include-hash="false"></script>
```

For programmatic loader use, `pageIdentity` is authoritative over loader attributes. Configure a static override without an inert policy:

```ts
pageIdentity: {
  override: '/workspaces/42',
}
```

Configure explicit query/hash policy separately when there is no override:

```ts
pageIdentity: {
  policy: { includeQuery: true, includeHash: false },
}
```

`override` can instead be a synchronous or asynchronous host/router resolver. It receives a frozen location snapshot and navigation generation; do not expose it through a global callback. Programmatic configuration replaces loader attributes when present, and query/hash policy is always explicit—ordinary query strings and hash fragments are never detected automatically. A late result from an older navigation generation is silently discarded and cannot replace the current identity.

## Environment injection

At Vite process start or production build time, the host supplies only these browser-template variables:

| Variable                         | Required value                                                                          |
| -------------------------------- | --------------------------------------------------------------------------------------- |
| `VITE_SCENE_GLASS_LOADER_URL`    | Direct Scene Glass loader URL on `http://127.0.0.1:<mcp-port>`; do not use `localhost`. |
| `VITE_SCENE_GLASS_PROJECT_ID`    | The configured Scene Glass `projectId`.                                                 |
| `VITE_SCENE_GLASS_PROJECT_TOKEN` | The current token from the host-owned secret source for that project.                   |

The MCP/server receives each current project token separately through the environment variable named by that project's `tokenEnv`. Public lifecycle startup reads the fixed `SCENE_GLASS_HOST_TOKEN` assignment from each selected host credential envelope and maps it to those distinct server bindings in memory; token values never enter configuration or descriptors.

Origin matching remains exact. During public lifecycle startup, each Vite project's effective startup pair is the currently re-derived `http://127.0.0.1:<vite-port>` and `http://localhost:<vite-port>` pair while its persisted setup Origin remains provenance. Manually constructed server startup uses the exact persisted `allowedOrigins` without this lifecycle-only replacement.

## Safe handling

- Inject the token from the host's deployment environment or secret manager. Do not commit a `.env` file with a token, print `import.meta.env`, or put the token in source maps, application state, `localStorage`, `sessionStorage`, cookies, analytics, errors, or console output.
- `VITE_` substitutions are browser-visible by design. Treat the emitted Vite artifact as local-capability material: restrict its distribution, do not publish it to logs or caches, and discard replaced build output during rotation.
- Do not add a browser fetch endpoint, websocket message, or global JavaScript function that returns the token. A document receives its token only through the loader tag.
- Keep the tag's `data-scg-navigation="spa"` value. The loader uses it for Vite single-page navigation; it does not make token refresh persistent.

## Startup and rotation

1. Set the three Vite variables in the host environment before starting the Vite development process or running the production build.
2. Start or rebuild the Vite host and open a fresh document at the configured `127.0.0.1` origin.
3. Rotate by updating the host-owned token, restarting the MCP/server, then restarting the Vite development host or rebuilding and redeploying the Vite artifact. A pre-rotation document receives `401` on its next Scene Glass request and must not retry or retrieve a replacement token; reload it to obtain the newly injected value.
