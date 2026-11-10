# BUILD REPORT — threatcheck

Rebuild of `com.ismalicious/mcp-server` v0.8.0 (remote-only)
as `@reneturcios/threatcheck` 0.1.0 / `io.github.CloudCorpRecords/threatcheck`.
**Full surface built: all 12 captured tools (12/12).**

## Fixture conflicts

**None.** The spec, the brief, and the fixture agree on the twelve tool
names and their required fields. Required fields as served, taken from
the fixture (`harness/fixtures/ismalicious-tools-original.json`):

- `scan_before_use` — required: `content`
- `check_url` — required: `url`
- `check_indicator` — required: `indicator`
- `get_cve` — required: `id`
- `recent_cves` — NO `required` key in its schema
- `search_indicators` — required: `keywords`
- `check_indicators` — required: `indicators`
- `scan_email` — NO `required` key in its schema
- `exploited_cves` — NO `required` key in its schema
- `watch_domain` — required: `domain`
- `watch_dependencies` — required: `content`, `name`
- `ack_finding` — required: `findingId`, `status`

The fixture's tool literals (name, title, description, inputSchema —
every captured tool carries a `title` key, and all twelve titles are
served) are served verbatim from `src/forward.ts`; the literals were
generated programmatically from the fixture JSON (parsed and
re-serialised by `/tmp/b39-threatcheck-gen.py`, never retyped) and
verified by the registration-integrity test (served tools/list
deep-equals the fixture's 12 tool objects, in order) and again by the
parity harness.

Judgment calls recorded in the spec, followed here: `check_indicator` /
`check_indicators` return a threat verdict about an indicator (an email
address or phone number included) — never personal data about a person,
and an email or phone number is never called clean; `watch_domain` /
`watch_dependencies` monitor the caller's own site or own lockfile/SBOM
and `ack_finding` manages the caller's own findings (own-workspace CRUD);
several tools are metered against the caller's own monthly quota, and
the 12-tool surface holds no purchase, top-up, checkout or key-minting
tool, so the surface is built in full.

## What was built

All 19 factory files under `builds/threatcheck/`:

- `package.json` (`@reneturcios/threatcheck` 0.1.0, bin
  `threatcheck` → `dist/cli.js`, mcpName
  `io.github.CloudCorpRecords/threatcheck`, deps exactly
  `@modelcontextprotocol/sdk ^1` + `zod ^3`; devDeps `@types/node ^20`,
  `tsx ^4`, `typescript ^5`)
- `server.json` (description exactly the prescribed 83-char string
  "Check URLs, indicators and CVEs against threat intelligence before you act on them.";
  npm entry carries `"version": "0.1.0"`; OCI entry
  `ghcr.io/cloudcorprecords/threatcheck:0.1.0` carries **no** version field)
- `Dockerfile` (node:20-alpine both stages; server-name label
  `io.modelcontextprotocol.server.name="io.github.CloudCorpRecords/threatcheck"`
  matches `server.json`)
- `tsconfig.json` (fleet-identical, 318 bytes), `.gitignore`,
  `package-lock.json`, `README.md` (fresh prose), `LICENSE` (MIT,
  Copyright (c) 2026 Rene Turcios), `CHANGELOG.md` (single 0.1.0 entry,
  2026-10-28)
- `src/index.ts`, `src/cli.ts`, `src/mcp.ts`, `src/types.ts`,
  `src/forward.ts` (core; exports `VERSION = "0.1.0"`)
- `test/forward.test.ts`
- `.github/workflows/{ci.yml, publish.yml, publish-container.yml,
  registry-publish.yml}` (container workflow: IMAGE
  `ghcr.io/cloudcorprecords/threatcheck`, smoke assertion on server name
  `threatcheck`)

Plus `BUILD-REPORT.md` (this file) and the `parity-out/` harness output.

## Design

- Forwarding client to `https://api.ismalicious.com/mcp` (pinned),
  overridable via `ISMALICIOUS_MCP_URL` (LABELLED RECONSTRUCTION).
  tools/call is forwarded as a streamable-HTTP JSON-RPC client:
  initialize (protocolVersion `2025-03-26`, clientInfo `threatcheck`) →
  notifications/initialized → tools/call, honouring `Mcp-Session-Id`
  when issued; session established lazily and reused per client.
  Plain-JSON and SSE replies both parsed; the matching-id message
  wins; upstream results pass through verbatim (including `isError`
  and extra fields such as `structuredContent`).
- When `ISMALICIOUS_API_KEY` is set, an `Authorization: Bearer <value>`
  header is sent on every upstream request (env NAME pinned by the
  original record's npm package entry; header NAME pinned by the
  registry record's own remote declaration; the Bearer form and the
  env forwarding are LABELLED RECONSTRUCTIONS — the capture was
  keyless). When unset, no key header is sent. No `X-API-Key` header
  is sent in either case. Both branches are covered by tests.
- Upstream failures (JSON-RPC error, non-2xx status, malformed body,
  throwing/timing-out fetch) surface as `threatcheck error:` text
  results (LABELLED RECONSTRUCTION).
- Registration via the MCP SDK **low-level** `Server` API
  (`ListToolsRequestSchema` / `CallToolRequestSchema` handlers)
  serving the fixture literals exactly; no `McpServer` + zod
  registration (per the task brief, overriding TEMPLATE.md §2 item 12).
  `src/mcp.ts` also exports `createServer` / `startMcpServer` /
  `handleCallTool` so the MCP layer is testable without a transport;
  the CLI's `mcp` subcommand starts it over stdio.
- Core takes an injectable fetch (`ForwardDeps.fetchFn`), so all tests
  run against a stubbed JSON-RPC upstream. No live network calls in
  tests; no live call claimed beyond the coordinator's tools/list
  capture.

## Labelled reconstructions (from the spec's Wire section)

- `ISMALICIOUS_MCP_URL` env override of the pinned endpoint
  `https://api.ismalicious.com/mcp`.
- Forwarding of `ISMALICIOUS_API_KEY` (env name pinned by the record's
  npm package entry) as `Authorization: Bearer <value>` (header name
  pinned by the registry record's remote declaration; Bearer form and
  env forwarding are reconstructions — the capture was keyless).
- The `threatcheck error:` failure rendering for upstream failures.

## Lockfile (Route 3, clean from birth)

Generated in the build dir with no `node_modules` present and no
pre-existing lockfile:
`npm install --package-lock-only --ignore-scripts --offline`.
Verified: parses, `name == @reneturcios/threatcheck`,
**128 package entries**, sha256
`9de7926a52d01e8a2690f4d8c1603113c77f41b3fdc19522249e3a4127eb5248`
(re-verified unchanged after the node_modules install).
Then `npm install --offline --ignore-scripts` in the build dir for
`node_modules`.

## Verification (all in the build dir unless noted)

- `npx tsc --noEmit` → exit 0
- `npm run build` → real `dist/` (cli.js, forward.js, mcp.js, types.js,
  index.js, all non-empty, with `.d.ts` + source maps)
- `node dist/cli.js --version` → `0.1.0`; unknown subcommand → usage on
  stderr, exit 2
- `npm test` → **68 tests, 68 pass, 0 fail** (8 suites: registration
  integrity — served tools deep-equal the fixture's full 12 tool
  objects, names in order, exactly the fixture's keys with titles,
  required fields per tool incl. the three tools with no `required`
  key, every property key in order for all 12, per-tool schema literals
  for check_indicator / get_cve / recent_cves / search_indicators /
  check_indicators / scan_email / exploited_cves / watch_domain /
  watch_dependencies / ack_finding, verdict wording, isKnownTool;
  session establishment/reuse/session-id handling, clientInfo/protocol
  version; env URL override, explicit url override, explicit-over-env
  precedence, blank-env fallback; Authorization Bearer present on every
  request when the key is set / absent when unset / no X-API-Key header
  in either case; verbatim argument forwarding for all 12 tools incl.
  fully-specified calls; verbatim result pass-through incl. upstream
  isError and SSE; JSON-RPC/init/malformed/no-result/HTTP/throw/timeout
  failures → `threatcheck error:`; parseRpcBody JSON + SSE + matching-id
  + [DONE] cases; MCP-layer MethodNotFound / InvalidParams validation;
  CLI --version / -v / unknown exit 2 / bad-JSON exit 2 / `mcp extra`
  exit 2)
- Parity: `python3 harness/parity.py --original
  harness/fixtures/ismalicious-tools-original.json --rebuild
  "stdio:node builds/threatcheck/dist/cli.js mcp" --out
  builds/threatcheck/parity-out` (run from `~/workspace/mcp-rebuild-100`)
  → **PASS, parity 100.0, 12/12 identical, no missing/extra/schema
  diffs** (see `parity-out/parity.json`)
- Consistency sweep: package.json version = server.json top-level =
  npm-entry version = OCI tag = core `VERSION` = CHANGELOG heading
  (0.1.0); package.json `mcpName` = server.json `name` = Dockerfile
  label; server.json description measured at 83 chars; OCI entry
  confirmed to have no `version` field.

Clean-room: all prose and code written fresh for threatcheck from the
spec; only the factory mechanics were patterned on the sibling imgpage
build (same forwarding-client class), and only the fixture's tool
literals are served verbatim.
