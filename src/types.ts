/**
 * threatcheck types.
 *
 * This package performs no threat lookup of its own. It is a
 * forwarding client: the captured tool surface is carried as
 * plain data (ToolDef entries served word-for-word for
 * tools/list) and every tools/call is dispatched to the hosted
 * isMalicious MCP endpoint through an injectable fetch, which
 * keeps the whole client testable without touching a network.
 */

/** One captured tool definition, served exactly as captured for tools/list. */
export interface ToolDef {
  name: string;
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
  [key: string]: unknown;
}

/** Arguments for a tool call, as a decoded JSON object. */
export type ToolArgs = Record<string, unknown>;

/** A tools/call result: upstream payloads pass through untouched; local failures use this shape too. */
export interface ToolResult {
  content?: unknown;
  isError?: boolean;
  [key: string]: unknown;
}

/** The slice of a fetch Response the forwarding client actually reads. */
export interface FetchResponseLike {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

/** Injectable fetch function, so tests can stand in for the upstream. */
export type FetchFn = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<FetchResponseLike>;

/** Injectable runtime dependencies for the forwarding client. */
export interface ForwardDeps {
  /** Fetch implementation. Defaults to the global fetch. */
  fetchFn?: FetchFn;
  /** Environment (ISMALICIOUS_MCP_URL, ISMALICIOUS_API_KEY). Defaults to process.env. */
  env?: Record<string, string | undefined>;
  /** Endpoint URL override. Defaults to env ISMALICIOUS_MCP_URL or the pinned default. */
  url?: string;
  /** Per-request timeout in milliseconds. Defaults to 30000. */
  timeoutMs?: number;
}
