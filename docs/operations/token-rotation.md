# Token rotation

This runbook rotates one Scene Glass project token without a compatibility period. The token is a browser-visible **local** capability: keep it in the host's secret source, not in Scene Glass configuration, source control, browser storage, or logs. The server configuration names that source with the project's `tokenEnv`; it does not contain the token value.

## Scope and preparation

1. Identify the project ID, its configured `tokenEnv`, and every host that injects that project's token.
2. Confirm each host is served from its configured, exact `http://` or `https://` origin. `localhost` and `127.0.0.1` are different origins. For the local MVP, use direct `http://127.0.0.1:<port>` URLs.
3. Generate the replacement token in the host-owned secret system. Do not put either value in a config file, command history, issue, console output, or browser storage.

## Rotation procedure

1. Replace the value of the project `tokenEnv` in the MCP/server launch environment with the replacement token. Leave the environment-variable name and project ID unchanged.
2. Restart the MCP/server so it discards the old environment and begins validating only the replacement token.
3. Refresh the host injection:
   - For a Vue/Vite host, restart the development host, or rebuild and redeploy the production host, with the replacement value in its environment.
   - For a static HTML host, re-render its host-template substitutions and redeploy the rendered document with the replacement value.
4. Open a **fresh document** from the configured exact origin. Confirm a Scene Glass request succeeds with the replacement token.
5. Keep one document that was open before the rotation. Its next Scene Glass request must receive `401`. Do not retry it with the old token, fetch a replacement token, or block the host application. A reload/redeployment supplies the replacement token to a fresh document.
6. Remove the old token from the host secret system only after the fresh-document check succeeds. Record the rotation time and project ID without recording either token.

## Required behavior

- The MCP/server accepts one current token per project. There is no dual-token grace period, previous-token fallback, or overlapping acceptance window.
- Hosts do not expose a token-refresh endpoint, global token getter, or automatic reauthentication path. The loader receives its injected token once and removes its `data-scg-token` attribute after reading it.
- An authentication failure is fail-open for the host: Scene Glass stops its own request; the Vue or static host remains usable.
- A `401` from a pre-rotation document is expected evidence that the old token is no longer accepted. Investigate a success with the old token immediately; it means the MCP/server was not restarted with the intended secret.

## Rollback

Do not restore a dual-token mode. If the replacement token was injected incorrectly, choose one token as the sole current value, update that value in both the MCP/server launch environment and affected host environments, restart/rebuild or re-render/redeploy as above, then repeat the fresh-document and old-document checks.
