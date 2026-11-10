/**
 * threatcheck MCP server. Tools: the 12 captured isMalicious
 * tools (see forward.ts).
 *
 * This file deliberately uses the low-level Server API
 * instead of McpServer: the high-level helper rebuilds the
 * schemas it serves from zod definitions, which would drift
 * from the captured tools/list. Here tools/list is answered
 * locally from the core's literal definitions — the captured
 * objects, served untouched — and every tools/call is
 * forwarded upstream.
 *
 * A forwarded result comes back unchanged, upstream isError
 * flag and extra fields included. An upstream failure
 * arrives as an isError result carrying a
 * `threatcheck error:` text, built by the forwarding client.
 * Unknown tool names are rejected with McpError
 * MethodNotFound, and non-object arguments with McpError
 * InvalidParams, before any network hop is attempted.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import {
  createClient,
  isKnownTool,
  TOOL_DEFS,
  VERSION,
  type ThreatcheckClient,
} from "./forward.js";
import type { ForwardDeps, ToolResult } from "./types.js";

/**
 * Validate and forward a single tools/call through
 * `client`. Exported so this layer can be exercised in
 * tests without a stdio transport.
 */
export async function handleCallTool(
  client: ThreatcheckClient,
  name: string,
  args: unknown,
): Promise<ToolResult> {
  if (!isKnownTool(name)) {
    throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
  }
  if (
    args !== undefined &&
    (typeof args !== "object" || args === null || Array.isArray(args))
  ) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Arguments for tool ${name} must be a JSON object`,
    );
  }
  return client.callTool(name, (args ?? {}) as Record<string, unknown>);
}

/** Build the stdio MCP server (transport not yet connected). */
export function createServer(deps: ForwardDeps = {}): Server {
  const client = createClient(deps);
  const server = new Server(
    { name: "threatcheck", version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const result = await handleCallTool(client, name, args);
    return result as never;
  });

  return server;
}

/** Connect the MCP server over stdio. */
export async function startMcpServer(deps: ForwardDeps = {}): Promise<void> {
  await createServer(deps).connect(new StdioServerTransport());
}
