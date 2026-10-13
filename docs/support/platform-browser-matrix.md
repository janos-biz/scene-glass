# Platform and browser support matrix

## Release authority

Scene Glass is macOS-first. Supported macOS filesystem evidence is the release authority for local durability and filesystem safety claims. Linux evidence is secondary conformance/smoke evidence. Windows is unsupported. Browser rows define verification expectations; they do not add a user-agent runtime block.

## Platform matrix

| Platform                                                                           | Runtime posture             | Required evidence                                                                                                                    | Release authority | Failure behavior                                                                                         |
| ---------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----------------- | -------------------------------------------------------------------------------------------------------- |
| macOS on a supported local filesystem                                              | Supported, macOS-first      | Platform probe, root/path checks, same-directory atomic rename, file and directory durability behavior, and fault/read-back evidence | Yes               | Do not bind unless the supported filesystem probe passes.                                                |
| Linux on the designated local filesystem                                           | Secondary conformance/smoke | Core contract and local-filesystem conformance/smoke evidence                                                                        | No                | A successful Linux smoke result does not establish full Linux support or replace macOS release evidence. |
| Windows                                                                            | Unsupported                 | None for MVP acceptance                                                                                                              | No                | Fail before bind with `SCG_PLATFORM_UNSUPPORTED`; do not offer a reduced-durability mode.                |
| Unknown platform, network/removable filesystem, or filesystem that fails the probe | Unsupported                 | None                                                                                                                                 | No                | Fail before bind. Do not bypass the probe or make a durability claim.                                    |

The macOS probe is part of the security and durability boundary, not a performance optimization. It verifies the local-filesystem conditions needed for root identity checks, atomic replacement, and durability handling. A platform that cannot establish those conditions is not a server host for this MVP.

## Browser matrix

| Browser engine | MVP coverage                       | Gate status              | Contract expectation                                                                                                                                                                          |
| -------------- | ---------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chromium       | Full end-to-end coverage           | Required release gate    | Vue 3 and static HTML hosts, loader fail-open behavior, direct-loopback exact-Origin/CORS requests, authentication/access failures, fresh-document token activation, and normal review flows. |
| Firefox        | Navigation and CORS smoke coverage | Required secondary smoke | Navigation lifecycle, loopback CORS behavior, and token-rotation state smoke. This is not equivalent to Chromium's full coverage.                                                             |
| WebKit         | No MVP acceptance coverage         | Non-gate                 | Results may be recorded as informational only. A passing or failing WebKit run does not change the supported scope.                                                                           |

The server and browser client do not inspect the user agent to block WebKit or to promote a browser based on its name. Browser support is established by the matrix above, not by runtime sniffing.

## Host behavior across the matrix

Both supported host shapes—Vue 3 and static HTML—use the same browser-client contract and provision the project capability from the host's startup configuration/environment snapshot. They remain fail-open: when the loader cannot start or the local service is unavailable, the host page continues without Scene Glass functionality.

The direct local endpoint is always literal `127.0.0.1`. An actual request must have an exact configured document Origin, then pass credential, project/session, and authorized-root checks. This is unchanged by platform or browser row.

## Evidence labels

Reports and release notes must label evidence precisely:

- **macOS full:** authority for supported local filesystem behavior.
- **Linux secondary:** conformance/smoke only; not a full-support claim.
- **Chromium full:** required browser acceptance coverage.
- **Firefox smoke:** navigation/CORS/rotation-state smoke only.
- **WebKit informational:** non-gate result.
- **Windows unsupported:** fail-before-bind contract, not an untested compatibility gap.

A label must not imply broader support than the evidence. In particular, Linux smoke does not establish macOS-equivalent durability, and WebKit results do not become an MVP release gate.
