# Changelog

## 0.1.0 (2026-10-28)

- First release: a forwarding client for the hosted isMalicious MCP server, serving the twelve captured tools locally for tools/list and forwarding every tools/call upstream over a streamable-HTTP JSON-RPC session (initialize, notifications/initialized, tools/call, honouring the Mcp-Session-Id header when issued).
- Tools: `scan_before_use`, `check_url`, `check_indicator`, `get_cve`, `recent_cves`, `search_indicators`, `check_indicators`, `scan_email`, `exploited_cves`, `watch_domain`, `watch_dependencies` and `ack_finding`. Several calls cost one request of the caller's own monthly quota, per the captured descriptions; the surface holds no purchase, top-up, checkout or key-minting tool.
- Upstream results pass through verbatim; upstream failures surface as `threatcheck error:` text results.
- One bin serves the CLI (one subcommand per tool, plus `--version`) and the stdio MCP server (`mcp` subcommand). Upstream endpoint overridable via `ISMALICIOUS_MCP_URL`; when `ISMALICIOUS_API_KEY` is set it is sent as an `Authorization: Bearer` header.
