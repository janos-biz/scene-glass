<h1 align="center">Scene Glass</h1>

<p align="center">
  <strong>Review the page you are building, directly in the browser.</strong><br />
  A local-first screen-review and annotation bridge for coding agents, Vue/React Vite apps, and static HTML.
</p>

> Scene Glass is an early-stage local development tool. Review generated host changes before approving setup, and keep the repository and project data backed up.

## What is Scene Glass?

Scene Glass connects a supported browser host to a loopback-only MCP service. It gives coding agents a structured view of the active page and stores review annotations with the project instead of in a remote service.

- Runs on literal `127.0.0.1`; it does not expose a wildcard network listener.
- Supports Vue 3/Vite, React/Vite SPA, and canonical static HTML hosts.
- Keeps authoritative annotations in `<project-root>/.scg/annotations`.
- Uses exact Origin, credential, project/session, and filesystem-root checks.
- Keeps host applications usable when Scene Glass is unavailable.
- Provides preview-and-approve onboarding, foreground start, and provenance-checked removal.

## Requirements

- macOS or Linux. Windows is unsupported.
- Node.js 24.
- Corepack and pnpm 10.34.5.
- Chromium for the full setup diagnostic.
- A separate Scene Glass checkout downloaded or cloned from GitHub and built once.

## Quick start

Download Scene Glass outside the host project, build the checkout once, then run its wrappers from the existing Vue or React project root. Scene Glass is not installed into the host's `node_modules`, and its source is never copied into the host:

```sh
git clone https://github.com/owen-ever/scene-glass.git /path/to/scene-glass
cd /path/to/scene-glass
corepack pnpm install --frozen-lockfile --ignore-scripts
node scripts/verify-bootstrap.mjs
corepack pnpm rebuild fs-ext esbuild
corepack pnpm run build:onboarding
corepack pnpm --filter @scene-glass/browser-client run build

cd /path/to/your-project
/path/to/scene-glass/scripts/setup

# Then, in two terminals from your project root:
npm run dev                          # your own Vite dev server (unchanged)
/path/to/scene-glass/scripts/start   # Scene Glass MCP + loader on 127.0.0.1:4175
```

`setup` inspects the current host project, configuration, credential authority, and supported topology; it shows a secret-redacted preview (including the exact loopback origins it will authorize) and requires approval before it writes or launches diagnostics. For Vite hosts the dev origin must be readable without executing the config; see [Supported hosts](#supported-hosts). **Your project needs no changes to satisfy this** — an ordinary `vite.config.ts` with any number of plugins works, and the `dev` script needs no added flags. After approval setup injects one async loader `<script>` into your root `index.html`, writes a gitignored `.env.development.local` credential, runs live MCP + a bounded synthetic-document browser diagnostic, and exits. It never installs into or copies Scene Glass source into your project, and it never touches `package.json`, lockfiles, or `node_modules`.

`start` accepts no parameters. It validates the active setup manifest, configuration, credential authority, and descriptors, then re-reads every registered Vite project's bounded `package.json` and `vite.config.ts`. It statically re-derives each declared dev port—an accepted literal CLI/config value, or Vite's deterministic default `5173` when both omit it—and applies the exact `http://127.0.0.1:<port>` / `http://localhost:<port>` pair only to the immutable in-memory startup snapshot. It does not execute Vite configuration, probe listeners, scan ports, or rewrite `~/.scg/config.json` or host descriptors. A dynamic, ambiguous, non-loopback, HTTPS, non-strict, conflicting, or changed-during-start declaration fails the whole startup before binding. Static HTML projects keep their persisted Origin policy.

After a `git pull`, `start` rebuilds the browser loader when its sources are newer than `packages/browser-client/dist/scene-glass-loader.js`. The server reads that bundle into memory as it starts and serves it for the life of the process, so a stale bundle is invisible: the page still connects and the panel still reports ready, only with the previous client. That rebuild is the plain Vite one — no native step, and it writes nothing outside its own `dist`. The onboarding CLI is never rebuilt from the wrapper, because its build compiles a native addon and clears its `dist` first; `start` only warns when `packages/onboarding/src` is newer than `packages/onboarding/dist/cli.js`, which `scripts/quickstart --rebuild` resolves. `SCG_SKIP_LOADER_BUILD=1` starts with whatever bundle is already on disk.

One foreground Scene Glass process on `127.0.0.1:4175` serves every registered project in that configuration home. Run each project's own `npm run dev` separately and open either exact loopback URL printed for its declared port. Port changes take effect on the next `scripts/start` after the literal package/config declarations are updated consistently; an already running Scene Glass process never hot-reloads them. Stop Scene Glass with `Ctrl+C`; all Vite dev servers keep running.

### Running the service

`start` runs in the foreground and binds `127.0.0.1:4175`. Run it from the host
project root, in its own terminal, alongside your own `npm run dev`:

```sh
cd /path/to/your-project
/path/to/scene-glass/scripts/start
```

A successful start prints what it bound and every project it serves:

```
scene-glass: listening on http://127.0.0.1:4175
scene-glass:   * my-app → http://127.0.0.1:5173  http://localhost:5173
scene-glass: 1 project(s) served; * is this directory. Open a project URL and hard-refresh once.
scene-glass: ready. Press Ctrl+C to stop (your Vite dev servers keep running).
```

`*` marks the project selected by the current directory; the origins are the ones
this startup re-derived, so a mis-declared port shows up here rather than as a
silent no-op. Open one of the printed URLs and hard-refresh once on first load.

**One process serves every registered project.** Do not start it per project — a
second instance fails its registry preflight because `4175` is taken. If `start`
reports `SCG_LIFECYCLE_PREFLIGHT_FAILED` at `start-registry-preflight`, check for
an instance you already have running:

```sh
lsof -nP -iTCP:4175 -sTCP:LISTEN
```

Use the one already running, or stop it with `Ctrl+C` first. Stopping Scene Glass
leaves every Vite dev server untouched.

**Restart after upgrading the checkout.** The loader bundle is read once at
startup, so a rebuilt `scene-glass-loader.js` does not reach the browser until
`start` is restarted and the page is hard-refreshed.

To remove setup-owned integration later:

```sh
cd /path/to/your-project
/path/to/scene-glass/scripts/uninstall
```

All three public lifecycle commands are parameter-free. The current directory selects the external host project, while the wrapper path selects the separate canonical Scene Glass checkout; use that same checkout and project root for setup, start, and uninstall.

### Hash or query routing

Page identity defaults to the URL path only; the hash and query string are ignored, so
memos on `#/a` and `#/b` (or `?tab=a` and `?tab=b`) share one page. If your app routes on
the hash or query string, opt in by adding one attribute to the loader `<script>` that
setup inserted into `index.html`:

```html
<script
  async
  src="%VITE_SCENE_GLASS_LOADER_URL%"
  ...
  data-scg-navigation="spa"
  data-scg-include-hash="true"
></script>
```

Use `data-scg-include-query="true"` for query-string routing. This edits the setup-owned
loader line, so `uninstall` will report it as altered (remove that one line manually when
uninstalling), and re-running `setup` regenerates the line without the attribute.

## Building from source

The native dependency and runtime bundle use a fail-closed bootstrap sequence. Do not replace it with a normal lifecycle-script install.

```sh
corepack pnpm install --frozen-lockfile --ignore-scripts
node scripts/verify-bootstrap.mjs
corepack pnpm rebuild fs-ext esbuild
corepack pnpm run build:onboarding
```

After the verified build completes, change to the supported host project's root and invoke the checkout's `scripts/setup` by path.

## Supported hosts

| Host                                    | Status    | Navigation mode | Notes                                                                                 |
| --------------------------------------- | --------- | --------------- | ------------------------------------------------------------------------------------- |
| Vue 3/Vite (`@vitejs/plugin-vue`)       | Supported | SPA             | Loader added to root `index.html`; you run your own Vite.                             |
| React/Vite SPA (`@vitejs/plugin-react`) | Supported | SPA             | Same framework-neutral loader contract.                                               |
| Canonical static HTML                   | Supported | Document        | Requires the canonical template and public root.                                      |
| Next.js                                 | Rejected  | —               | Setup exits before mutation.                                                          |
| PWA/service worker hosts                | Rejected  | —               | Setup exits before mutation (including `vite-plugin-pwa`).                            |
| Statically unresolvable dev origin      | Rejected  | —               | Dynamic `server.port`, non-loopback `server.host`, or both supported plugins at once. |

The dev origin must be readable without executing the config: loopback HTTP and a deterministic port — a literal `server.port`, a literal `--port` on the `dev` script, or Vite's default `5173`. Ports `80` and `4175`, HTTPS that is not literally `false`, a non-loopback `server.host`, more than one `server` block, and a non-literal port are rejected.

Only three facts are read from `vite.config.ts`: the framework plugin, `server.port`, and `server.strictPort`. **Everything else is your own business** — plugins, imports, aliases, and any other option are ignored, and the file never has to match a particular shape.

`strictPort` is read but not required. Without it Vite moves to the next free port when yours is taken; the page then runs on an origin Scene Glass did not authorize, so the loader simply does not attach. Compare the origins printed by `start` with your browser's address bar if that happens.

Setup and every start still fail closed on an unsupported host shape rather than guessing. Setup and every start fail closed on unsupported host shapes rather than guessing, and a failed or declined preview leaves the checkout, home configuration, credentials, descriptors, and processes unchanged.

## Configuration and data

Scene Glass keeps global configuration, project data, setup state, and host integration artifacts separate:

| Location                                | Purpose                                                                                           | `uninstall` behavior                                                                                            |
| --------------------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `~/.scg/config.json`                    | Schema-v1 project configuration and environment-variable names                                    | Restores or removes only the setup-owned project record; preserves unrelated records                            |
| `~/.scg/credential-authorities.v1.json` | Secretless credential path and stable device/inode authority per project                          | Removes only the selected setup-owned entry; preserves unrelated entries and retains a canonical empty registry |
| `~/.scg/onboarding.lock`                | Shared serialization lock for setup, start preparation, recovery, and removal                     | Retained as coordination state; it is never used as project ownership evidence                                  |
| `<project-root>/.scg/annotations`       | Authoritative per-page annotations                                                                | Never reads, rewrites, or removes annotations                                                                   |
| `<project-root>/.scg/onboarding`        | Per-host secretless lifecycle manifest, WAL, and terminal receipt                                 | Removes an active manifest only after provenance preflight; may retain a terminal receipt or recovery evidence  |
| `<project-root>/.scg/runtime`           | Setup-owned host descriptor and integration helper                                                | Removes only artifacts still proven setup-owned; never removes annotations                                      |
| `<project-root>/index.html`             | Your Vite root template; setup inserts one owned loader `<script>` line                           | Removes exactly the owned loader line, preserving your other edits; conflicts if it was altered                 |
| `<project-root>/.env.development.local` | Gitignored host-owned credential (four `VITE_SCENE_GLASS_*`/`SCENE_GLASS_HOST_TOKEN` assignments) | Deletes it only when setup created it; preserves an adopted credential                                          |
| Scene Glass source checkout             | Separate executable source and user work                                                          | Never copied into the host and never removed                                                                    |

Where the lifecycle is supplied an explicit CLI configuration path, it takes precedence over `SCENE_GLASS_CONFIG_PATH`, which takes precedence over the home default. The public scripts intentionally expose no flags, so ordinary script use selects `SCENE_GLASS_CONFIG_PATH` when set or `~/.scg/config.json` otherwise.
Legacy active lifecycle state under `<checkout>/.scg/onboarding` remains readable only when its manifest selects the invoked host root. New setup state is per host, so multiple projects can retain independent provenance while sharing one config home and Scene Glass checkout.

`config.json` contains each token environment-variable name, not a token value or credential path. The sibling authority registry contains only the approved credential path and stable device/inode identity; it never contains token bytes or token-derived digests. The raw token stays in the selected host-owned, gitignored environment source.

### Legacy home migration

The default configuration moved from `~/.config/scene-glass` to `~/.scg` without changing the schema-v1 meaning:

- **Only the legacy location exists:** setup moves it transactionally and does not discard it before the new location is durable.
- **Both locations exist:** setup uses `~/.scg` and preserves the legacy location unchanged.
- **Neither exists:** setup creates a schema-v1 configuration at `~/.scg/config.json`.

Project annotations are not part of this migration and remain under each project root.

## Setup safety model

1. Inspect build artifacts, configuration, host shape, credentials, and browser availability using bounded reads only.
2. Display a bounded, secret-redacted summary of operation kinds and hunk counts plus the approval digest; target paths and token material are not printed.
3. Ask for explicit approval.
4. Run native self-tests and an empty Chromium smoke test.
5. Reuse a valid host credential or generate exactly one token with at least 256 bits of entropy.
6. Apply configuration, credential-authority registry, host, descriptor, and manifest changes through one shared config-home lock and a WAL transaction.
7. Verify the resulting authority and run real initialize, `notifications/initialized`, ping, loader, and browser diagnostics.
8. Publish the active manifest only after every check succeeds; otherwise compensate or leave an explicit recovery-required receipt.

Setup never stores the raw token in JSON, `.scg`, lifecycle manifests, logs, browser storage, or support output.

## Safe uninstall

`./scripts/uninstall` is provenance-first: it reads the active setup manifest and validates every owned target before changing anything. If a managed hunk, file identity, fingerprint, credential authority, or provenance record conflicts, it exits without modifying any target.

A successful uninstall reverses only still-identifiable setup-owned integration. It preserves:

- the Scene Glass source checkout;
- every `<project-root>/.scg/annotations` file;
- unrelated host edits and files;
- adopted credentials that existed before setup;
- unrelated configuration records; and
- a legacy config directory when both legacy and new locations existed.

It records a terminal uninstalled receipt so a repeated uninstall reports the already-removed state without deleting additional data. A WAL or recovery-required state is a stop condition, not permission to delete lifecycle files manually.

> **Warning:** a credential source that setup itself created (as opposed to an adopted
> pre-existing credential) is deleted irreversibly once the durable uninstall decision
> commits. Stop the MCP service and any managed host first, and copy the token elsewhere
> beforehand if you still need it; uninstall does not back up secret material.

## Troubleshooting

### Find out which check failed

The lifecycle prints the failing _stage_ but not the check behind it, so
`failure stages: inspection.` on its own is not actionable. Rerun with the
debug switch to print the underlying error and its causes:

```sh
SCG_LIFECYCLE_DEBUG=1 /path/to/scene-glass/scripts/setup
```

`scripts/quickstart` sets it already. Frequent messages:

| Message                                             | Meaning                                                                                                                                                                         |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SCG_ONBOARDING_COMMAND_INVALID` (no stage printed) | The dev script and `vite.config.ts` do not declare a usable dev origin — see the next section.                                                                                  |
| `credential environment collision in .env`          | A `VITE_SCENE_GLASS_*` or `SCENE_GLASS_HOST_TOKEN` assignment exists in a shared env file; setup owns those keys in `.env.development.local`. Remove them from the shared file. |
| `allowed origins must be unique across projects`    | Another registered project already claims this port. Use a different `--port`, or unregister that project.                                                                      |
| `SCG_LIFECYCLE_NOT_ACTIVE` from `uninstall`         | No active manifest under `.scg/onboarding`, so there is nothing the command may reverse.                                                                                        |

### Memos land in "유실 데이터" (orphaned)

The memo itself is safe — annotations are never rewritten, only the _binding_ to
an element was lost. Scene Glass re-finds an element by `data-scg-id` first, and
otherwise by a fingerprint of its tag, stable attributes, ancestor signatures and
text. Two shapes defeat the fingerprint:

- **Rows in a data grid.** The only distinguishing token is a positional
  attribute such as `aria-rowindex`, which changes on sort, filter or refresh.
- **Bare layout elements.** A `<div>` with no attributes, no text and only
  `<div>` ancestors fingerprints identically to dozens of its siblings.

The fix is host-side: stamp a stable `data-scg-id` on the elements you want to
annotate, and Scene Glass will bind exactly. Derive it from identity, not
position — a business key plus a column id for grid cells, and a structural path
from the app root for everything else. A dev-only pass that stamps the subtree
after each render is enough; the attribute only has to exist while you review.

### Setup reports an unsupported host

Confirm that the current directory is a supported host and that the command came from the same Scene Glass checkout used for its setup. For a Vue/React Vite host, discovery requires all of:

- `package.json` with a string `name` and a direct `scripts.dev` starting with `vite` (a bare `vite` is fine; only the `--host 127.0.0.1`, `--host localhost`, `--port N`, and `--strictPort` flags may be added);
- a `vite.config.ts` (not `.js`) using exactly one of `@vitejs/plugin-vue` or `@vitejs/plugin-react`. Additional plugins and options are ignored;
- a loopback dev origin: `server.host` may be omitted (Vite's default is fine — setup authorizes both the `http://127.0.0.1:<port>` and `http://localhost:<port>` origin spellings), and an explicit host must be `'127.0.0.1'` or `'localhost'`; any other host is rejected;
- a literal `server.port` number when a port is configured (a dynamic port cannot be authorized statically);
- a root `index.html` with exactly one `</head>` and no `public/index.html`.

Next.js, service workers/PWA (including `vite-plugin-pwa`), and statically unresolvable dev origins are intentionally rejected.

### Setup stops at the approval preview

No mutation has occurred. Review the operation summary and approval digest, then rerun setup. Do not edit lifecycle state to bypass the preview digest.

### Setup or uninstall reports a provenance conflict

Do not delete `.scg/onboarding` or force an inverse operation. Preserve the checkout and host files, inspect the reported managed target, and reconcile the unexpected edit before retrying. Conflict handling is intentionally no-write.

### Start fails with `Cannot find module .../packages/onboarding/dist/cli.js`

The checkout was never built successfully. The onboarding build clears
`packages/onboarding/dist` before compiling its native addon, so a failed native step
leaves no `dist/cli.js` and the wrappers cannot run. Build the checkout and read the
first failing step:

```sh
cd /path/to/scene-glass
corepack pnpm install --frozen-lockfile --ignore-scripts
node scripts/verify-bootstrap.mjs
corepack pnpm rebuild fs-ext esbuild
corepack pnpm run build:onboarding
corepack pnpm --filter @scene-glass/browser-client run build
ls -l packages/onboarding/dist/cli.js packages/browser-client/dist/scene-glass-loader.js
```

A missing C/C++ toolchain is the usual cause: run `xcode-select --install` on macOS (
node-gyp also needs `python3`), or install `build-essential` and `python3` on Linux.

### Start rejects a credential or descriptor

Restarting does not repair replaced or unsafe authorities. Verify that the host-owned credential file still has the approved path, owner, mode, and inode, then rerun setup if the integration must be re-established.

Device numbers are the one exception. A volume is assigned its `st_dev` at mount time, so a reboot can renumber every recorded device while each file stays exactly where setup left it. Start reconciles that case on its own: when every recorded inode still matches the entry at its recorded path and all of them sit on one device, it repoints the stored device numbers and continues. It repairs nothing else — a changed inode, a wrong entry kind, identities spread across volumes, or a descriptor edited beyond its device numbers all leave the stored records untouched so the checks below still report the real conflict.

### Setup reports ambiguous loader evidence

A stale build output (for example `dist/index.html` from a previous `npm run build`) can
still contain a Scene Glass loader tag, which setup detects as an existing, ambiguous
install and refuses to proceed. Remove the loader `<script>` line from the stale build
artifact (or delete the build output directory) and rerun `setup`. Your live root
`index.html` is unaffected.

### The host page loads without Scene Glass

That is the expected fail-open host behavior. Confirm the checkout's `scripts/start` (MCP on 4175) and your own `npm run dev` are both running, open a fresh document at your dev origin (the `http://127.0.0.1:<port>` or `http://localhost:<port>` URL your dev server actually serves — both are authorized), and reload.

## Development

```sh
corepack pnpm run build
corepack pnpm run test
corepack pnpm run lint
corepack pnpm run format:check
```

Focused onboarding verification:

```sh
corepack pnpm run bootstrap:verify
corepack pnpm run build:onboarding
corepack pnpm run test:g001
```

Architecture, operations, security, and integration details live under [`docs/`](docs/).
