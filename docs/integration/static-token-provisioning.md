# Static HTML token provisioning

Use this contract for a canonical static HTML host. Scene Glass is optional: the page must remain usable when the loader fails, the local MCP is unavailable, or a Scene Glass request receives `401`.

## Automated onboarding and removal

From the canonical static host root, invoke every lifecycle command through the same canonical Scene Glass checkout:

```sh
cd /path/to/your-static-project
/path/to/scene-glass/scripts/setup
/path/to/scene-glass/scripts/start
# Later, after stopping start:
/path/to/scene-glass/scripts/uninstall
```

`setup` previews the secret-redacted configuration, credential, and host-artifact plan and requires approval before it mutates anything. For this canonical static host, its preview includes a loader marker in the canonical template. `start` is parameter-free foreground MCP-only startup on `127.0.0.1:4175`; it does not daemonize or start a host server. The user starts the host server separately. `uninstall` validates provenance before restoration or removal and preserves the checkout, `<project-root>/.scg/annotations`, adopted credentials, and unrelated edits. A provenance conflict or recovery-required state changes no target: preserve `<project-root>/.scg/onboarding` and reconcile the reported change rather than deleting lifecycle files.

This automation accepts only the canonical static HTML topology. Next.js, PWA/service-worker evidence, and noncanonical or ambiguous templates are rejected without a fallback. The manual rendering contract below applies to a canonical static template; it does not permit unsupported host shapes.

## Host template contract

Have the static-site renderer substitute this one-line asynchronous loader tag for each deployed document:

```text
<script async src="{{SCENE_GLASS_LOADER_URL}}" data-scg-project="{{SCENE_GLASS_PROJECT_ID}}" data-scg-token="{{SCENE_GLASS_PROJECT_TOKEN}}" data-scg-navigation="document"></script>
```

`{{...}}` denotes the host renderer's environment-backed substitution syntax; use its equivalent delimiters when required, while preserving the attribute names and values. The loader reads `data-scg-token` once and removes it. Do not add a runtime token endpoint, a global token function, or client-side persistence.

## Page identity

The [authoritative page-identity contract](./vite-token-provisioning.md#page-identity) is shared by every host. The static-rendering examples below apply that contract to rendered documents.
By default, Scene Glass uses only `location.pathname` as the canonical page identity. Ordinary query strings and hash fragments stay excluded; the loader never infers that either is meaningful.

Configure a non-empty static override with `data-scg-page-identity`; it wins over the browser pathname, query, and hash. Use `data-scg-include-query` and `data-scg-include-hash` only to include location parts. Their boolean values must be exact lowercase `true` or `false`; absent attributes and `false` both exclude the corresponding query or hash.

```text
<script async src="{{SCENE_GLASS_LOADER_URL}}" data-scg-project="{{SCENE_GLASS_PROJECT_ID}}" data-scg-token="{{SCENE_GLASS_PROJECT_TOKEN}}" data-scg-navigation="document" data-scg-page-identity="/manuals/install"></script>
```

```text
<script async src="{{SCENE_GLASS_LOADER_URL}}" data-scg-project="{{SCENE_GLASS_PROJECT_ID}}" data-scg-token="{{SCENE_GLASS_PROJECT_TOKEN}}" data-scg-navigation="document" data-scg-include-query="true" data-scg-include-hash="false"></script>
```

For programmatic loader use, configure the authoritative `pageIdentity` option rather than adding a global callback. Configure a static override without an inert policy:

```ts
pageIdentity: {
  override: '/manuals/install',
}
```

Configure explicit query/hash policy separately when there is no override:

```ts
pageIdentity: {
  policy: { includeQuery: true, includeHash: false },
}
```

`override` can instead be a synchronous or asynchronous host/router resolver. Its context contains a frozen location snapshot and navigation generation. Programmatic configuration replaces loader attributes when present, and it must choose query/hash policy explicitly; ordinary query strings and fragments are never inferred. A late result from an older navigation generation is silently discarded and cannot replace the current identity.

## Renderer inputs

Provide these values to the static renderer from the host-owned deployment environment or secret manager:

| Renderer input              | Required value                                                                          |
| --------------------------- | --------------------------------------------------------------------------------------- |
| `SCENE_GLASS_LOADER_URL`    | Direct Scene Glass loader URL on `http://127.0.0.1:<mcp-port>`; do not use `localhost`. |
| `SCENE_GLASS_PROJECT_ID`    | The configured Scene Glass `projectId`.                                                 |
| `SCENE_GLASS_PROJECT_TOKEN` | The project's current host-owned token.                                                 |

The MCP/server gets the same current token from its own launch environment under the configured `tokenEnv` name. Its configuration contains the name of that environment variable, not the token value.

The rendered document's full origin must exactly match a configured `allowedOrigins` entry. For local operation, render and serve it as `http://127.0.0.1:<static-port>` and configure that exact origin. Do not interchange it with `http://localhost:<static-port>`.

## Safe handling

- Keep the unrendered template token-free. Do not commit rendered documents containing a token, secret files, or deployment logs that print substitutions.
- Do not write the injected value to `localStorage`, `sessionStorage`, cookies, page state, analytics, error reports, source maps, or the console. The browser-visible token exists only in the loader tag until the loader removes its attribute.
- A static render necessarily makes the local capability visible to anyone who can read that rendered document. Limit access to the local deployment, prevent artifact/log/cache publication, and replace the deployed output on every rotation.
- Do not provide a fetch, websocket, or global JavaScript token supplier after the page has loaded. A new document gets a token only from a newly rendered tag.
- Keep `data-scg-navigation="document"`. Static hosts use full document navigation rather than SPA navigation.

## Render, deploy, and rotate

1. Set the three renderer inputs in the host environment, render the static document, and deploy it at the configured exact `127.0.0.1` origin.
2. Open a fresh document and confirm its Scene Glass request succeeds.
3. Rotate by updating the host-owned secret, restarting the MCP/server, re-rendering the static document with the replacement value, and redeploying it. A document that was already open must receive `401` on its next Scene Glass request; it must not retry or fetch a new token. Reloading obtains the token from the newly rendered document.
