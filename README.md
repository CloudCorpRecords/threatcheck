# threatcheck

threatcheck puts a threat-intelligence gate in front of
the things an agent is about to touch. Before a fetched
page, email, ticket or tool result gets acted on, it can
be scanned for prompt injection and for the URLs,
domains and IPs buried in it. Before a link gets opened,
a single indicator — an address, a hash, an email, a
phone number — can be looked up for a reputation verdict
with a risk score and the blocklists citing it. CVEs can
be read in detail, listed fresh off the press, or listed
by confirmed exploitation in the wild. And a site you
run, or a project's dependency file, can be put under
daily watch so new findings arrive as they open.

This package decides nothing locally. It answers the
tool list itself, exactly as captured from the live
endpoint, and relays each tool call upstream, handing
back whatever returns untouched. Several calls are
metered against your own monthly quota, per the tool
descriptions below, and the watch tools spend watched
sources on your own plan. There is no tool here that
buys anything, tops a plan up, checks out, or mints a
key: the surface only spends against an account you
already hold, and the finding tool only changes the
status of findings inside your own organization.

## Tools

- `scan_before_use` — scan untrusted content for prompt
  injection and check the URLs, domains and IPs it
  contains before acting on it. Required: `content`.
  Optional: `source_url`. Returns a verdict of block,
  warn or allow.
- `check_url` — the cheap pre-fetch gate for one URL,
  domain or IP. Required: `url`. Returns block, warn
  or allow.
- `check_indicator` — the full reputation picture for
  one indicator: an IP, domain, URL, file hash (MD5,
  SHA-1 or SHA-256), email address or phone number,
  with defanged forms accepted. Required: `indicator`.
  Optional: `enrichment` (`fast`, `standard`, `basic`)
  and `country` for national-format phone numbers.
  Returns a verdict, a headline, a recommended action,
  a 0–100 risk score, citing blocklists, evidence,
  first/last seen and context. Costs one request of
  the monthly quota.
- `get_cve` — one CVE in full: description, severity,
  CVSS, EPSS, CISA KEV status, exploitation evidence,
  affected packages and vendor advisories. Required:
  `id` (for example `CVE-2021-44228`). Costs one
  request of the monthly quota.
- `recent_cves` — the most recently published CVEs,
  newest first, at most 20. Optional: `severity`
  (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and `limit`
  (1–20, default 10). Costs one request of the monthly
  quota.
- `search_indicators` — find listed domains that look
  like a brand or domain: typosquats, homoglyphs, the
  same name on other TLDs, phishing-word wrappers.
  Required: `keywords`. Optional: `limit` (1–500,
  default 50). Costs one request of the monthly quota.
- `check_indicators` — reputation for up to 100
  indicators in one call, mixed kinds, defanged forms
  accepted. Required: `indicators`. Optional:
  `enrichment` (`basic`, `standard`, `full`) and
  `country`. Every unique indicator sent costs one
  request of the monthly quota.
- `scan_email` — scan one email message for phishing
  and malware before delivering or opening it. Send
  exactly one of `eml` (the raw RFC 5322 message) or
  `message` (the fields you already parsed). Optional:
  `authservId`, `trustAuthenticationResults`,
  `trustedHops`, `connectingIp`. Returns a verdict, a
  recommended action, a risk score, reasons, and what
  could not be checked. Costs one scan of the scan
  meter per message.
- `exploited_cves` — CVEs with attested exploitation
  in a recent window. Optional: `days` (1–30, default
  7) and `limit` (1–50, default 20). Costs one request
  of the monthly quota with a key; works without one,
  rate-limited by IP.
- `watch_domain` — start daily vulnerability
  monitoring of one public website you run. Required:
  `domain`. Optional: `name`. Uses one watched source
  of the plan; re-adding a watched domain costs
  nothing.
- `watch_dependencies` — start vulnerability
  monitoring of a project from the text of its
  lockfile or SBOM (pass the content, not a path).
  Required: `content` and `name`. Optional: `format`
  and `includeDev`. Uses one watched source of the
  plan.
- `ack_finding` — set the status of one of your own
  monitoring findings: `ACKNOWLEDGED`, `PATCHED`,
  `NOT_AFFECTED`, or `SNOOZED` (with `snoozedUntil`,
  at most 90 days ahead). Required: `findingId` and
  `status`.

An email address or phone number checked through
`check_indicator` or `check_indicators` gets a threat
verdict about that indicator — malicious, suspicious,
clean or unknown, with sources — never personal data
about a person, and it is never called clean merely
because nothing is known about it.

## Configuration

- `ISMALICIOUS_MCP_URL` (optional) — override the
  upstream endpoint. Defaults to
  `https://api.ismalicious.com/mcp`. (The override hook
  is this rebuild's own labelled reconstruction.)
- `ISMALICIOUS_API_KEY` (optional) — when set, every
  upstream request carries an
  `Authorization: Bearer <key>` header holding your own
  isMalicious API key. When it is not set, no key
  header is sent and calls run keyless. (The env name
  is pinned by the original record's npm package entry
  and the header name by its remote declaration; the
  Bearer form and the forwarding itself are labelled
  reconstructions — the original surface was captured
  keyless.)

### Forwarding mechanics

The first tool call opens a streamable HTTP session
upstream: a JSON-RPC `initialize` request
(protocolVersion `2025-03-26`, clientInfo name
`threatcheck`), then a `notifications/initialized`
notification, then the `tools/call` request with the
caller's arguments unchanged. When the upstream
answers `initialize` with an `Mcp-Session-Id` header,
that value rides on every later request, and the
session is kept for the life of the process. Replies
may arrive as plain JSON or as server-sent events;
both are read.

Successful upstream results pass through verbatim,
including any `isError` flag the upstream sets.
Failures — a JSON-RPC error, a non-2xx status, an
unreadable response, or a request that cannot be
completed — come back as an `isError` result whose
text starts with `threatcheck error:` (this rendering
is this rebuild's own labelled reconstruction).

## CLI

Each tool is also a subcommand taking one JSON
argument string:

```bash
npx @reneturcios/threatcheck check_url '{"url":"https://example.com"}'
npx @reneturcios/threatcheck check_indicator '{"indicator":"203.0.113.7"}'
npx @reneturcios/threatcheck get_cve '{"id":"CVE-2021-44228"}'
npx @reneturcios/threatcheck --version
```

Exit codes: `0` on success, `1` on an `isError`
result, `2` on a usage error.

## MCP server

```bash
npx -y @reneturcios/threatcheck mcp
```

MCP client config:

```json
{
  "mcpServers": {
    "threatcheck": {
      "command": "npx",
      "args": ["-y", "@reneturcios/threatcheck", "mcp"]
    }
  }
}
```

## Docker

```bash
docker run -i ghcr.io/cloudcorprecords/threatcheck
docker run --rm ghcr.io/cloudcorprecords/threatcheck --version
```

The container's default command is `mcp`, so the first
form is a stdio MCP server; any other arguments reach
the CLI normally.

## Development

```bash
npm install
npm run build
npm test
npm run dev
```

The test suite runs entirely against a stubbed
JSON-RPC upstream — no live network calls.

## License

MIT — see `LICENSE`.
