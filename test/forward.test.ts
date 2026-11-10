import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  ThreatcheckClient,
  callTool,
  createClient,
  DEFAULT_ENDPOINT_URL,
  isKnownTool,
  parseRpcBody,
  PROTOCOL_VERSION,
  TOOL_DEFS,
  TOOL_NAMES,
  VERSION,
} from "../src/forward.js";
import { handleCallTool } from "../src/mcp.js";
import type {
  FetchFn,
  FetchResponseLike,
  ToolDef,
  ToolResult,
} from "../src/types.js";

/**
 * Every test runs against a stubbed JSON-RPC upstream that
 * speaks the streamable-HTTP session flow
 * (initialize -> notifications/initialized -> tools/call).
 * No live network: the real isMalicious endpoint is never
 * contacted from this suite.
 */

const FIXTURE_URL = new URL(
  "../../../harness/fixtures/ismalicious-tools-original.json",
  import.meta.url,
);
const FIXTURE_AVAILABLE = existsSync(FIXTURE_URL);
const fixture = (
  FIXTURE_AVAILABLE
    ? JSON.parse(readFileSync(FIXTURE_URL, "utf-8"))
    : { tools: [] }
) as {
  tools: ToolDef[];
};
/**
 * Publish-survival guard (Wave 25 preflight, proven Wave 24 pattern):
 * the parity fixture lives in the build harness, outside the published
 * repo tree, so fixture-dependent tests skip cleanly when it is absent;
 * with the fixture present they run in full, with no skips.
 */
function skipWithoutFixture(t: {
  skip: (message: string) => void;
}): boolean {
  if (FIXTURE_AVAILABLE) return false;
  t.skip("parity fixture lives in the build harness, not the repo tree");
  return true;
}


const ALL_TOOLS = [
  "scan_before_use",
  "check_url",
  "check_indicator",
  "get_cve",
  "recent_cves",
  "search_indicators",
  "check_indicators",
  "scan_email",
  "exploited_cves",
  "watch_domain",
  "watch_dependencies",
  "ack_finding",
];

const SAMPLE_RESULT = {
  content: [{ type: "text", text: "{\"verdict\":\"allow\"}" }],
  structuredContent: { verdict: "allow" },
};

interface Recorded {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

interface FakeOptions {
  callResult?: Record<string, unknown>;
  callBodyText?: string;
  callError?: Record<string, unknown>;
  callStatus?: number;
  initError?: Record<string, unknown>;
  throwOn?: "initialize" | "tools/call";
  sessionId?: string | null;
  hangOnCall?: boolean;
  sse?: boolean;
}

function rawResponse(
  status: number,
  bodyText: string,
  headers: Record<string, string> = {},
): FetchResponseLike {
  const lowered = new Map(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => lowered.get(name.toLowerCase()) ?? null },
    text: async () => bodyText,
  };
}

function jsonResponse(
  status: number,
  payload: unknown,
  headers: Record<string, string> = {},
) {
  return rawResponse(status, JSON.stringify(payload), headers);
}

function fakeUpstream(options: FakeOptions = {}): {
  fetchFn: FetchFn;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const fetchFn: FetchFn = async (url, init) => {
    const body = JSON.parse(init?.body ?? "{}") as Record<string, unknown>;
    calls.push({ url, headers: init?.headers ?? {}, body });
    const method = body.method as string;
    if (options.throwOn === method) throw new Error("connection reset");
    if (method === "initialize") {
      if (options.initError !== undefined) {
        return jsonResponse(200, {
          jsonrpc: "2.0",
          id: body.id,
          error: options.initError,
        });
      }
      const headers: Record<string, string> = {};
      const sessionId =
        options.sessionId === undefined ? "sess-abc" : options.sessionId;
      if (sessionId !== null) headers["mcp-session-id"] = sessionId;
      return jsonResponse(
        200,
        {
          jsonrpc: "2.0",
          id: body.id,
          result: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: {},
            serverInfo: { name: "ismalicious", version: "0.8.0" },
          },
        },
        headers,
      );
    }
    if (method === "notifications/initialized") {
      return rawResponse(202, "");
    }
    if (method === "tools/call") {
      if (options.hangOnCall) {
        return new Promise<FetchResponseLike>((_resolve, reject) => {
          const signal = init?.signal;
          if (signal) {
            if (signal.aborted) {
              reject(new Error("aborted"));
              return;
            }
            signal.addEventListener("abort", () => reject(new Error("aborted")));
          }
        });
      }
      if (options.callBodyText !== undefined) {
        return rawResponse(options.callStatus ?? 200, options.callBodyText);
      }
      if (options.callError !== undefined) {
        return jsonResponse(200, {
          jsonrpc: "2.0",
          id: body.id,
          error: options.callError,
        });
      }
      const result = options.callResult ?? SAMPLE_RESULT;
      const payload = { jsonrpc: "2.0", id: body.id, result };
      if (options.sse) {
        return rawResponse(
          200,
          `event: message\ndata: ${JSON.stringify(payload)}\n\n`,
        );
      }
      return jsonResponse(options.callStatus ?? 200, payload);
    }
    return jsonResponse(200, {});
  };
  return { fetchFn, calls };
}

function stubbed(options: FakeOptions = {}, extra: Record<string, unknown> = {}) {
  const upstream = fakeUpstream(options);
  const client = new ThreatcheckClient({
    fetchFn: upstream.fetchFn,
    env: {},
    ...extra,
  });
  return { client, calls: upstream.calls };
}

function textOf(result: ToolResult): string {
  const content = result.content as Array<{ type: string; text: string }>;
  return content[0].text;
}

function methodsOf(calls: Recorded[]): string[] {
  return calls.map((c) => c.body.method as string);
}

function propsOf(tool: ToolDef): Record<string, Record<string, unknown>> {
  return (
    tool.inputSchema as {
      properties: Record<string, Record<string, unknown>>;
    }
  ).properties;
}

function toolByName(name: string): ToolDef {
  const found = TOOL_DEFS.find((t) => t.name === name);
  assert.ok(found, `tool ${name} missing`);
  return found;
}

/* ------------------------------------------------------------------ */

describe("registration integrity (captured surface)", () => {
  it("serves exactly the fixture's 12 tools, deep-equal, in order", (t) => {
    if (skipWithoutFixture(t)) return;
    assert.equal(fixture.tools.length, 12);
    assert.deepEqual(TOOL_DEFS, fixture.tools);
  });

  it("serves the 12 tool names in fixture order", () => {
    assert.deepEqual(TOOL_NAMES, ALL_TOOLS);
  });

  it("carries exactly the fixture's keys on each tool, title included", () => {
    for (const tool of TOOL_DEFS) {
      assert.deepEqual(Object.keys(tool).sort(), [
        "description",
        "inputSchema",
        "name",
        "title",
      ]);
      assert.equal(typeof tool.title, "string");
      assert.notEqual(tool.title, "");
    }
  });

  it("carries exactly the fixture's required fields per tool", () => {
    const expected: Record<string, string[] | undefined> = {
      scan_before_use: ["content"],
      check_url: ["url"],
      check_indicator: ["indicator"],
      get_cve: ["id"],
      recent_cves: undefined,
      search_indicators: ["keywords"],
      check_indicators: ["indicators"],
      scan_email: undefined,
      exploited_cves: undefined,
      watch_domain: ["domain"],
      watch_dependencies: ["content", "name"],
      ack_finding: ["findingId", "status"],
    };
    for (const tool of TOOL_DEFS) {
      assert.deepEqual(
        (tool.inputSchema as { required?: string[] }).required,
        expected[tool.name],
        tool.name,
      );
    }
  });

  it("carries no required key at all on recent_cves, scan_email and exploited_cves", () => {
    for (const name of ["recent_cves", "scan_email", "exploited_cves"]) {
      assert.equal("required" in toolByName(name).inputSchema, false, name);
    }
  });

  it("carries every fixture property, in order, for all 12 tools", (t) => {
    if (skipWithoutFixture(t)) return;
    for (let i = 0; i < 12; i += 1) {
      assert.deepEqual(
        Object.keys(propsOf(TOOL_DEFS[i])),
        Object.keys(propsOf(fixture.tools[i])),
        TOOL_DEFS[i].name,
      );
    }
    assert.deepEqual(Object.keys(propsOf(toolByName("check_indicator"))), [
      "indicator",
      "enrichment",
      "country",
    ]);
    assert.deepEqual(Object.keys(propsOf(toolByName("scan_email"))), [
      "eml",
      "message",
      "authservId",
      "trustAuthenticationResults",
      "trustedHops",
      "connectingIp",
    ]);
    assert.deepEqual(Object.keys(propsOf(toolByName("watch_dependencies"))), [
      "content",
      "name",
      "format",
      "includeDev",
    ]);
  });

  it("carries check_indicator's schema constraints verbatim", () => {
    const schema = toolByName("check_indicator").inputSchema as {
      additionalProperties?: unknown;
    };
    assert.equal(schema.additionalProperties, false);
    const props = propsOf(toolByName("check_indicator"));
    assert.equal(props.indicator.type, "string");
    assert.equal(props.indicator.minLength, 1);
    assert.equal(props.indicator.maxLength, 2048);
    assert.deepEqual(props.enrichment.enum, ["fast", "standard", "basic"]);
    assert.equal(props.country.minLength, 2);
    assert.equal(props.country.maxLength, 2);
  });

  it("carries get_cve's id pattern verbatim", () => {
    const props = propsOf(toolByName("get_cve"));
    assert.equal(props.id.type, "string");
    assert.equal(props.id.pattern, "^[Cc][Vv][Ee]-\\d{4}-\\d{4,}$");
    assert.equal(
      (toolByName("get_cve").inputSchema as { additionalProperties?: unknown })
        .additionalProperties,
      false,
    );
  });

  it("carries recent_cves' severity enum and limit bounds verbatim", () => {
    const props = propsOf(toolByName("recent_cves"));
    assert.deepEqual(props.severity.enum, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
    assert.equal(props.limit.type, "integer");
    assert.equal(props.limit.minimum, 1);
    assert.equal(props.limit.maximum, 20);
  });

  it("carries search_indicators' keyword and limit bounds verbatim", () => {
    const props = propsOf(toolByName("search_indicators"));
    assert.equal(props.keywords.minLength, 2);
    assert.equal(props.keywords.maxLength, 128);
    assert.equal(props.limit.minimum, 1);
    assert.equal(props.limit.maximum, 500);
  });

  it("carries check_indicators' batch constraints verbatim", () => {
    const props = propsOf(toolByName("check_indicators"));
    const indicators = props.indicators as unknown as Record<string, unknown>;
    assert.equal(indicators.type, "array");
    assert.equal(indicators.minItems, 1);
    assert.equal(indicators.maxItems, 100);
    assert.deepEqual(indicators.items, {
      type: "string",
      minLength: 3,
      maxLength: 2048,
    });
    assert.deepEqual(props.enrichment.enum, ["basic", "standard", "full"]);
  });

  it("carries scan_email's message shape verbatim", () => {
    const tool = toolByName("scan_email");
    assert.equal(
      (tool.inputSchema as { additionalProperties?: unknown })
        .additionalProperties,
      false,
    );
    const props = propsOf(tool);
    assert.equal(props.eml.minLength, 1);
    assert.equal(props.trustedHops.minimum, 1);
    assert.equal(props.trustedHops.maximum, 10);
    assert.equal(props.trustAuthenticationResults.type, "boolean");
    const message = props.message as unknown as Record<string, unknown>;
    assert.equal(message.additionalProperties, false);
    assert.deepEqual(
      Object.keys(message.properties as Record<string, unknown>),
      ["headers", "from", "replyTo", "returnPath", "subject", "text", "html", "attachments"],
    );
  });

  it("carries exploited_cves' window bounds verbatim", () => {
    const props = propsOf(toolByName("exploited_cves"));
    assert.equal(props.days.minimum, 1);
    assert.equal(props.days.maximum, 30);
    assert.equal(props.limit.minimum, 1);
    assert.equal(props.limit.maximum, 50);
  });

  it("carries watch_domain's length caps verbatim", () => {
    const props = propsOf(toolByName("watch_domain"));
    assert.equal(props.domain.maxLength, 2048);
    assert.equal(props.name.maxLength, 120);
  });

  it("carries watch_dependencies' format enum and content cap verbatim", () => {
    const props = propsOf(toolByName("watch_dependencies"));
    assert.deepEqual(props.format.enum, [
      "package-lock.json",
      "composer.lock",
      "requirements.txt",
      "Gemfile.lock",
      "Cargo.lock",
      "cyclonedx.json",
    ]);
    assert.equal(props.content.maxLength, 5242880);
    assert.equal(props.name.maxLength, 120);
    assert.equal(props.includeDev.type, "boolean");
  });

  it("carries ack_finding's status enum and snooze field verbatim", () => {
    const props = propsOf(toolByName("ack_finding"));
    assert.deepEqual(props.status.enum, [
      "ACKNOWLEDGED",
      "PATCHED",
      "NOT_AFFECTED",
      "SNOOZED",
    ]);
    assert.equal(props.findingId.maxLength, 64);
    assert.equal(props.snoozedUntil.format, "date-time");
  });

  it("carries the captured verdict wording in the scan descriptions", () => {
    assert.match(toolByName("scan_before_use").description, /block \| warn \| allow/);
    assert.match(toolByName("check_url").description, /block \| warn \| allow/);
    assert.match(toolByName("check_indicator").description, /malicious, suspicious, clean or unknown/);
  });

  it("isKnownTool recognises all 12 built tools and rejects others", () => {
    for (const name of ALL_TOOLS) assert.equal(isKnownTool(name), true, name);
    assert.equal(isKnownTool("check_domain"), false);
    assert.equal(isKnownTool(""), false);
  });
});

/* ------------------------------------------------------------------ */

describe("session establishment and reuse", () => {
  it("runs initialize, notifications/initialized, then tools/call in order", async () => {
    const { client, calls } = stubbed();
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, undefined);
    assert.deepEqual(methodsOf(calls), [
      "initialize",
      "notifications/initialized",
      "tools/call",
    ]);
    assert.ok(calls.every((call) => call.url === DEFAULT_ENDPOINT_URL));
    assert.equal(DEFAULT_ENDPOINT_URL, "https://api.ismalicious.com/mcp");
    for (const call of calls) {
      assert.equal(call.headers["Content-Type"], "application/json");
      assert.equal(call.headers["Accept"], "application/json, text/event-stream");
    }
    assert.equal(calls[0].headers["Mcp-Session-Id"], undefined);
    assert.equal(calls[1].headers["Mcp-Session-Id"], "sess-abc");
    assert.equal(calls[2].headers["Mcp-Session-Id"], "sess-abc");
  });

  it("sends clientInfo name threatcheck and the pinned protocol version on initialize", async () => {
    const { client, calls } = stubbed();
    await client.callTool("get_cve", { id: "CVE-2021-44228" });
    const params = calls[0].body.params as Record<string, unknown>;
    assert.equal(params.protocolVersion, PROTOCOL_VERSION);
    assert.equal(PROTOCOL_VERSION, "2025-03-26");
    assert.deepEqual(params.capabilities, {});
    assert.deepEqual(params.clientInfo, { name: "threatcheck", version: VERSION });
  });

  it("establishes the session lazily once and reuses it on later calls", async () => {
    const { client, calls } = stubbed();
    await client.callTool("check_url", { url: "https://example.com" });
    await client.callTool("recent_cves", {});
    assert.deepEqual(methodsOf(calls), [
      "initialize",
      "notifications/initialized",
      "tools/call",
      "tools/call",
    ]);
    assert.equal(calls[3].headers["Mcp-Session-Id"], "sess-abc");
    assert.notEqual(calls[2].body.id, calls[3].body.id);
  });

  it("sends no session header when the upstream issues none", async () => {
    const { client, calls } = stubbed({ sessionId: null });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, undefined);
    assert.ok(calls.every((call) => call.headers["Mcp-Session-Id"] === undefined));
  });

  it("honours the ISMALICIOUS_MCP_URL env override", async () => {
    const upstream = fakeUpstream();
    const client = new ThreatcheckClient({
      fetchFn: upstream.fetchFn,
      env: { ISMALICIOUS_MCP_URL: "https://staging.example.com/mcp" },
    });
    await client.callTool("check_url", { url: "https://example.com" });
    assert.ok(
      upstream.calls.every((call) => call.url === "https://staging.example.com/mcp"),
    );
  });

  it("honours an explicit url override over the default endpoint", async () => {
    const upstream = fakeUpstream();
    const client = createClient({
      fetchFn: upstream.fetchFn,
      env: {},
      url: "https://alt.example.com/mcp",
    });
    await client.callTool("check_url", { url: "https://example.com" });
    assert.ok(upstream.calls.every((call) => call.url === "https://alt.example.com/mcp"));
  });

  it("prefers an explicit url override over the env override", async () => {
    const upstream = fakeUpstream();
    const client = createClient({
      fetchFn: upstream.fetchFn,
      env: { ISMALICIOUS_MCP_URL: "https://env.example.com/mcp" },
      url: "https://explicit.example.com/mcp",
    });
    await client.callTool("check_url", { url: "https://example.com" });
    assert.ok(
      upstream.calls.every((call) => call.url === "https://explicit.example.com/mcp"),
    );
  });

  it("falls back to the pinned endpoint when the env override is blank", async () => {
    const upstream = fakeUpstream();
    const client = new ThreatcheckClient({
      fetchFn: upstream.fetchFn,
      env: { ISMALICIOUS_MCP_URL: "   " },
    });
    await client.callTool("check_url", { url: "https://example.com" });
    assert.ok(upstream.calls.every((call) => call.url === DEFAULT_ENDPOINT_URL));
  });
});

/* ------------------------------------------------------------------ */

describe("upstream key header", () => {
  it("sends Authorization: Bearer on every request when ISMALICIOUS_API_KEY is set", async () => {
    const upstream = fakeUpstream();
    const client = new ThreatcheckClient({
      fetchFn: upstream.fetchFn,
      env: { ISMALICIOUS_API_KEY: "im-key-7" },
    });
    await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(upstream.calls.length, 3);
    assert.ok(
      upstream.calls.every(
        (call) => call.headers["Authorization"] === "Bearer im-key-7",
      ),
    );
  });

  it("sends no Authorization header when ISMALICIOUS_API_KEY is unset", async () => {
    const { client, calls } = stubbed();
    await client.callTool("check_url", { url: "https://example.com" });
    assert.ok(calls.every((call) => call.headers["Authorization"] === undefined));
  });

  it("never sends an X-API-Key header, with or without a key", async () => {
    const withKey = fakeUpstream();
    const keyed = new ThreatcheckClient({
      fetchFn: withKey.fetchFn,
      env: { ISMALICIOUS_API_KEY: "im-key-7" },
    });
    await keyed.callTool("check_url", { url: "https://example.com" });
    assert.ok(withKey.calls.every((call) => call.headers["X-API-Key"] === undefined));
    const { client, calls } = stubbed();
    await client.callTool("check_url", { url: "https://example.com" });
    assert.ok(calls.every((call) => call.headers["X-API-Key"] === undefined));
  });
});

/* ------------------------------------------------------------------ */

describe("tools/call forwarding", () => {
  it("forwards a scan_before_use call verbatim", async () => {
    const { client, calls } = stubbed();
    const args = { content: "visit hxxp://bad.example now", source_url: "https://example.com/page" };
    await client.callTool("scan_before_use", args);
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "scan_before_use");
    assert.deepEqual(params.arguments, args);
  });

  it("forwards a check_url call verbatim", async () => {
    const { client, calls } = stubbed();
    await client.callTool("check_url", { url: "https://example.com/login" });
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "check_url");
    assert.deepEqual(params.arguments, { url: "https://example.com/login" });
  });

  it("forwards a fully-specified check_indicator verbatim", async () => {
    const { client, calls } = stubbed();
    const args = { indicator: "06 12 34 56 78", enrichment: "standard", country: "FR" };
    await client.callTool("check_indicator", args);
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "check_indicator");
    assert.deepEqual(params.arguments, args);
  });

  it("forwards a get_cve call verbatim", async () => {
    const { client, calls } = stubbed();
    await client.callTool("get_cve", { id: "CVE-2021-44228" });
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "get_cve");
    assert.deepEqual(params.arguments, { id: "CVE-2021-44228" });
  });

  it("forwards recent_cves and exploited_cves filter arguments verbatim", async () => {
    const { client, calls } = stubbed();
    await client.callTool("recent_cves", { severity: "CRITICAL", limit: 5 });
    await client.callTool("exploited_cves", { days: 14, limit: 30 });
    const first = calls[2].body.params as Record<string, unknown>;
    const second = calls[3].body.params as Record<string, unknown>;
    assert.deepEqual(first.arguments, { severity: "CRITICAL", limit: 5 });
    assert.equal(second.name, "exploited_cves");
    assert.deepEqual(second.arguments, { days: 14, limit: 30 });
  });

  it("forwards a search_indicators call verbatim", async () => {
    const { client, calls } = stubbed();
    const args = { keywords: "paypal", limit: 25 };
    await client.callTool("search_indicators", args);
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "search_indicators");
    assert.deepEqual(params.arguments, args);
  });

  it("forwards a fully-specified check_indicators verbatim", async () => {
    const { client, calls } = stubbed();
    const args = {
      indicators: ["203.0.113.7", "example.com", "d41d8cd98f00b204e9800998ecf8427e"],
      enrichment: "basic",
      country: "GB",
    };
    await client.callTool("check_indicators", args);
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "check_indicators");
    assert.deepEqual(params.arguments, args);
  });

  it("forwards a scan_email call with a parsed message verbatim", async () => {
    const { client, calls } = stubbed();
    const args = {
      message: {
        headers: [{ name: "From", value: "Sender <sender@example.com>" }],
        subject: "Urgent: verify your account",
        text: "Click here",
      },
      trustAuthenticationResults: true,
    };
    await client.callTool("scan_email", args);
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "scan_email");
    assert.deepEqual(params.arguments, args);
  });

  it("forwards watch_domain and watch_dependencies verbatim", async () => {
    const { client, calls } = stubbed();
    await client.callTool("watch_domain", { domain: "shop.example.com", name: "Shop" });
    await client.callTool("watch_dependencies", {
      content: "{\"name\":\"shop-frontend\",\"lockfileVersion\":3}",
      name: "shop-frontend",
      format: "package-lock.json",
      includeDev: true,
    });
    const first = calls[2].body.params as Record<string, unknown>;
    const second = calls[3].body.params as Record<string, unknown>;
    assert.deepEqual(first.arguments, { domain: "shop.example.com", name: "Shop" });
    assert.equal(second.name, "watch_dependencies");
    assert.deepEqual(second.arguments, {
      content: "{\"name\":\"shop-frontend\",\"lockfileVersion\":3}",
      name: "shop-frontend",
      format: "package-lock.json",
      includeDev: true,
    });
  });

  it("forwards an ack_finding call verbatim", async () => {
    const { client, calls } = stubbed();
    const args = {
      findingId: "xfnd_123",
      status: "SNOOZED",
      snoozedUntil: "2026-11-15T00:00:00Z",
    };
    await client.callTool("ack_finding", args);
    const params = calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "ack_finding");
    assert.deepEqual(params.arguments, args);
  });

  it("passes the upstream result through verbatim, including extra fields", async () => {
    const { client } = stubbed();
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.deepEqual(out, SAMPLE_RESULT);
  });

  it("passes an upstream isError result through untouched", async () => {
    const upstreamResult = {
      content: [{ type: "text", text: "quota exhausted" }],
      isError: true,
    };
    const { client } = stubbed({ callResult: upstreamResult });
    const out = await client.callTool("get_cve", { id: "CVE-2021-44228" });
    assert.deepEqual(out, upstreamResult);
  });

  it("reads an SSE-framed tools/call response", async () => {
    const { client } = stubbed({ sse: true });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, undefined);
    assert.deepEqual(out, SAMPLE_RESULT);
  });

  it("the one-shot callTool helper forwards under the right tool name", async () => {
    const upstream = fakeUpstream();
    const out = await callTool(
      "check_indicator",
      { indicator: "example.com" },
      { fetchFn: upstream.fetchFn, env: {} },
    );
    assert.equal(out.isError, undefined);
    const params = upstream.calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "check_indicator");
    assert.deepEqual(params.arguments, { indicator: "example.com" });
  });
});

/* ------------------------------------------------------------------ */

describe("upstream failures surface as threatcheck error text", () => {
  it("maps a JSON-RPC error to `threatcheck error: <message>`", async () => {
    const { client } = stubbed({
      callError: { code: -32000, message: "upstream lookup failed" },
    });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.equal(textOf(out), "threatcheck error: upstream lookup failed");
  });

  it("maps an initialize JSON-RPC error to threatcheck error text", async () => {
    const { client } = stubbed({
      initError: { code: -32600, message: "bad initialize" },
    });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.equal(textOf(out), "threatcheck error: bad initialize");
  });

  it("maps an unparseable upstream response to a malformed-response error", async () => {
    const { client } = stubbed({ callBodyText: "<html>oops</html>" });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.equal(textOf(out), "threatcheck error: malformed response");
  });

  it("maps a response with no result object to a malformed-response error", async () => {
    const { client } = stubbed({
      callBodyText: '{"jsonrpc":"2.0","id":3,"result":null}',
    });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.equal(textOf(out), "threatcheck error: malformed response");
  });

  it("maps a non-2xx upstream status to threatcheck error text", async () => {
    const { client } = stubbed({ callBodyText: "internal error", callStatus: 500 });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.equal(textOf(out), "threatcheck error: HTTP 500");
  });

  it("maps a throwing fetch to threatcheck error text", async () => {
    const { client } = stubbed({ throwOn: "tools/call" });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.match(textOf(out), /^threatcheck error: /);
  });

  it("maps a throwing initialize fetch to threatcheck error text", async () => {
    const { client } = stubbed({ throwOn: "initialize" });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.equal(textOf(out), "threatcheck error: connection reset");
  });

  it("maps a timed-out call to threatcheck error text", async () => {
    const { client } = stubbed({ hangOnCall: true }, { timeoutMs: 20 });
    const out = await client.callTool("check_url", { url: "https://example.com" });
    assert.equal(out.isError, true);
    assert.match(textOf(out), /^threatcheck error: /);
  });
});

/* ------------------------------------------------------------------ */

describe("parseRpcBody", () => {
  it("parses plain JSON and picks the message with the matching id", () => {
    const body = '{"jsonrpc":"2.0","id":7,"result":{"ok":true}}';
    assert.deepEqual(parseRpcBody(body, 7), {
      jsonrpc: "2.0",
      id: 7,
      result: { ok: true },
    });
  });

  it("parses SSE data lines", () => {
    const body =
      'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"ok":true}}\n\n';
    assert.deepEqual(parseRpcBody(body, 2), {
      jsonrpc: "2.0",
      id: 2,
      result: { ok: true },
    });
  });

  it("picks the matching id among several SSE messages", () => {
    const body =
      'data: {"jsonrpc":"2.0","id":1,"result":{"n":1}}\n\n' +
      'data: {"jsonrpc":"2.0","id":2,"result":{"n":2}}\n\n';
    assert.deepEqual(parseRpcBody(body, 2), {
      jsonrpc: "2.0",
      id: 2,
      result: { n: 2 },
    });
  });

  it("ignores the SSE [DONE] sentinel", () => {
    const body =
      'data: {"jsonrpc":"2.0","id":4,"result":{"ok":true}}\ndata: [DONE]\n';
    assert.deepEqual(parseRpcBody(body, 4), {
      jsonrpc: "2.0",
      id: 4,
      result: { ok: true },
    });
  });

  it("returns null for empty and unparseable bodies", () => {
    assert.equal(parseRpcBody(""), null);
    assert.equal(parseRpcBody("not json at all"), null);
    assert.equal(parseRpcBody("[1,2,3]"), null);
  });
});

/* ------------------------------------------------------------------ */

describe("MCP layer validation", () => {
  it("rejects an unknown tool with MethodNotFound before any network hop", async () => {
    const upstream = fakeUpstream();
    const client = createClient({ fetchFn: upstream.fetchFn, env: {} });
    await assert.rejects(
      () => handleCallTool(client, "not_a_tool", {}),
      (err: unknown) =>
        err instanceof McpError && err.code === ErrorCode.MethodNotFound,
    );
    assert.equal(upstream.calls.length, 0);
  });

  it("rejects array arguments with InvalidParams before any network hop", async () => {
    const upstream = fakeUpstream();
    const client = createClient({ fetchFn: upstream.fetchFn, env: {} });
    await assert.rejects(
      () => handleCallTool(client, "check_url", ["nope"]),
      (err: unknown) =>
        err instanceof McpError && err.code === ErrorCode.InvalidParams,
    );
    assert.equal(upstream.calls.length, 0);
  });

  it("rejects string arguments with InvalidParams before any network hop", async () => {
    const upstream = fakeUpstream();
    const client = createClient({ fetchFn: upstream.fetchFn, env: {} });
    await assert.rejects(
      () => handleCallTool(client, "get_cve", "CVE-2021-44228"),
      (err: unknown) =>
        err instanceof McpError && err.code === ErrorCode.InvalidParams,
    );
    assert.equal(upstream.calls.length, 0);
  });

  it("forwards a valid check_url call through the MCP layer unchanged", async () => {
    const upstream = fakeUpstream();
    const client = createClient({ fetchFn: upstream.fetchFn, env: {} });
    const out = await handleCallTool(client, "check_url", { url: "https://example.com" });
    assert.deepEqual(out, SAMPLE_RESULT);
    const params = upstream.calls[2].body.params as Record<string, unknown>;
    assert.deepEqual(params.arguments, { url: "https://example.com" });
  });

  it("forwards a valid get_cve call through the MCP layer unchanged", async () => {
    const upstream = fakeUpstream();
    const client = createClient({ fetchFn: upstream.fetchFn, env: {} });
    const out = await handleCallTool(client, "get_cve", { id: "CVE-2021-44228" });
    assert.deepEqual(out, SAMPLE_RESULT);
    const params = upstream.calls[2].body.params as Record<string, unknown>;
    assert.equal(params.name, "get_cve");
  });

  it("treats omitted arguments as an empty object", async () => {
    const upstream = fakeUpstream();
    const client = createClient({ fetchFn: upstream.fetchFn, env: {} });
    const out = await handleCallTool(client, "recent_cves", undefined);
    assert.deepEqual(out, SAMPLE_RESULT);
    const params = upstream.calls[2].body.params as Record<string, unknown>;
    assert.deepEqual(params.arguments, {});
  });
});

/* ------------------------------------------------------------------ */

describe("CLI", () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const cliPath = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

  function runCli(args: string[]) {
    return spawnSync(process.execPath, ["--import", "tsx", cliPath, ...args], {
      cwd: root,
      encoding: "utf8",
      timeout: 30000,
    });
  }

  it("--version prints 0.1.0 and exits 0", () => {
    const res = runCli(["--version"]);
    assert.equal(res.status, 0);
    assert.equal(res.stdout.trim(), "0.1.0");
    assert.equal(res.stdout.trim(), VERSION);
  });

  it("-v prints 0.1.0 and exits 0", () => {
    const res = runCli(["-v"]);
    assert.equal(res.status, 0);
    assert.equal(res.stdout.trim(), "0.1.0");
  });

  it("an unknown command prints usage on stderr and exits 2", () => {
    const res = runCli(["not-a-tool"]);
    assert.equal(res.status, 2);
    assert.match(res.stderr, /Usage:/);
  });

  it("a non-JSON argument exits 2", () => {
    const res = runCli(["check_url", "not json"]);
    assert.equal(res.status, 2);
  });

  it("a JSON array argument exits 2", () => {
    const res = runCli(["check_url", "[]"]);
    assert.equal(res.status, 2);
  });

  it("extra arguments after mcp exit 2", () => {
    const res = runCli(["mcp", "extra"]);
    assert.equal(res.status, 2);
  });
});
