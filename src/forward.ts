/**
 * threatcheck core: a forwarding client for the hosted
 * isMalicious MCP server.
 *
 * No verdict is computed here. tools/list is answered from
 * literal definitions captured live from the upstream
 * server (name, title, description and inputSchema exactly
 * as captured). A tools/call is relayed upstream over a
 * streamable-HTTP JSON-RPC session: an initialize POST, a
 * notifications/initialized POST, then the tools/call POST.
 * If the upstream hands back an Mcp-Session-Id header on
 * initialize, it is echoed on every later request of the
 * session. The session is opened on the first forwarded
 * call and then kept for the life of the client.
 *
 * The endpoint is pinned to https://api.ismalicious.com/mcp
 * and may be replaced through the ISMALICIOUS_MCP_URL
 * environment variable (that override is a labelled
 * reconstruction). When ISMALICIOUS_API_KEY is set — the
 * env name is pinned by the original record's npm package
 * entry — every upstream request carries an
 * `Authorization: Bearer <value>` header (the header name
 * is pinned by the registry record's remote declaration;
 * the Bearer form and the env forwarding are labelled
 * reconstructions, since the capture was taken keyless).
 * When the key is unset, no key header goes out.
 *
 * A successful upstream result is handed back exactly as
 * it arrived, isError flag and any extra fields included.
 * Failures — an upstream JSON-RPC error, a non-2xx status,
 * an unparseable body, or a fetch that throws or times
 * out — become an isError result whose text begins with
 * `threatcheck error:` (that rendering is a labelled
 * reconstruction). A reply may be plain JSON or SSE
 * (`data:` lines); the JSON-RPC message whose id matches
 * the request wins.
 */
import type {
  FetchFn,
  FetchResponseLike,
  ForwardDeps,
  ToolArgs,
  ToolDef,
  ToolResult,
} from "./types.js";

export const VERSION = "0.1.0";

export const DEFAULT_ENDPOINT_URL = "https://api.ismalicious.com/mcp";

export const DEFAULT_TIMEOUT_MS = 30000;

export const PROTOCOL_VERSION = "2025-03-26";

/* ------------------------------------------------------------------ */
/* Tool definitions (tools/list literals, verbatim from the live       */
/* capture in harness/fixtures/ismalicious-tools-original.json;        */
/* generated programmatically by parsing and re-serialising the        */
/* fixture JSON with /tmp/b39-threatcheck-gen.py, never retyped)       */
/* ------------------------------------------------------------------ */

export const TOOL_DEFS: ToolDef[] = [
  {
    "name": "scan_before_use",
    "title": "Scan untrusted content before use",
    "description": "Scan untrusted content for prompt injection and check any URLs/domains/IPs it contains against threat intelligence, BEFORE acting on it. Returns a verdict of block | warn | allow. Call this on any web page, email, ticket, tool result, or document fetched from an untrusted source.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "content": {
          "type": "string",
          "description": "The untrusted content to scan."
        },
        "source_url": {
          "type": "string",
          "description": "Optional: the URL the content was fetched from."
        }
      },
      "required": [
        "content"
      ]
    }
  },
  {
    "name": "check_url",
    "title": "Check a link before fetching it",
    "description": "Check a single URL, domain, or IP against threat intelligence before fetching it. Returns block | warn | allow. Use as a pre-fetch gate; use check_indicator when you need the full reputation picture (score, sources, timeline).",
    "inputSchema": {
      "type": "object",
      "properties": {
        "url": {
          "type": "string",
          "description": "The URL/domain/IP to check."
        }
      },
      "required": [
        "url"
      ]
    }
  },
  {
    "name": "check_indicator",
    "title": "Check indicator reputation",
    "description": "The one tool for any single indicator: an IP address, domain, URL, file hash (MD5, SHA-1 or SHA-256; an imphash is looked up as an MD5), email address or phone number. Defanged input (hxxp://, [.], [@]) is accepted. Returns a verdict (malicious, suspicious, clean or unknown), a headline you can relay as is, recommendedAction (block, review, allow or unverified), a 0-100 risk score, the threat blocklists that cite it, up to three evidence reasons, first/last seen, and network, registration or file context. An email address or phone number is never called clean: not being in our sources is unknown / unverified; its answer adds the sender domain's reputation, disposable and MX facts, or the E.164 form of the number. `infrastructure` says what the entity is known as (cloud range, CDN, Tor exit, VPN, crawler, allowlist) without being a verdict. SHA-512, TLSH, ssdeep and input that is none of the six kinds (an address in a form the API cannot read, digits that are not a phone number, a number written with letters, a host that is not a dotted domain name) are refused before any request, at no cost. The default level, fast, answers from cached intelligence without a live DNS, WHOIS or OTX call (a hash nobody has cached may wait up to ~2.5 s on CIRCL); facets not cached yet are listed in meta.pending, and one re-check after a few seconds may complete them; if they are still pending then, keep the answer and do not re-check again. Costs one request of the monthly quota; check_url is the cheaper pre-fetch gate for a link.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "indicator": {
          "type": "string",
          "description": "The IP, domain, URL, file hash (MD5, SHA-1 or SHA-256), email address or phone number to check. Defanged forms are accepted, and so are full-width characters, a display-name address (Name <user@example.com>), a mailto:, tel:, sms: or callto: link, and a labelled hash (sha256:…).",
          "minLength": 1,
          "maxLength": 2048
        },
        "enrichment": {
          "type": "string",
          "enum": [
            "fast",
            "standard",
            "basic"
          ],
          "description": "\"fast\" (default): cached intelligence only, no live upstream call before the answer; facets not cached yet are listed in meta.pending and fetched in the background, so one re-check after a few seconds may complete them (a hash no source has cached may wait up to a few seconds on CIRCL). \"standard\": may call live upstreams (DNS, OTX, CIRCL) before answering; seconds on an entity nobody has checked recently. \"basic\": verdict and blocklists only, no risk score. Email addresses and phone numbers are answered from cached data at every level."
        },
        "country": {
          "type": "string",
          "minLength": 2,
          "maxLength": 2,
          "description": "ISO 3166-1 alpha-2 country (FR, GB, DE…) for a phone number written in national format, e.g. 06 12 34 56 78 with FR. Not needed for +… or 00… numbers; without it a 10-digit number is read as North American. Ignored for other indicators."
        }
      },
      "required": [
        "indicator"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "get_cve",
    "title": "Look up a CVE",
    "description": "One CVE by id: description, severity, CVSS score and vector, EPSS exploitation probability, CISA KEV status (date added, due date, required action, known ransomware use), exploitation evidence where recorded (CISA SSVC none/poc/active, Exploit-DB ids, Nuclei template, Microsoft's exploited flag), affected packages with introduced and fixed versions (OSV.dev, first 8), vendor advisories (CSAF, first 4), publication dates and references (NVD, KEV, EPSS, CERT-FR, GitHub advisories, Exploit-DB). No recorded exploitation evidence does not mean the CVE is not exploited. This is the only CVE lookup path; do not guess other routes. Costs one request of the monthly quota.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "CVE identifier, e.g. CVE-2021-44228. Case-insensitive.",
          "pattern": "^[Cc][Vv][Ee]-\\d{4}-\\d{4,}$"
        }
      },
      "required": [
        "id"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "recent_cves",
    "title": "Latest published CVEs",
    "description": "Most recently published CVEs, newest first, optionally filtered by severity. At most 20 items, each with id, severity, CVSS, publication date and a one-line title. Follow up with get_cve for EPSS, KEV, exploitation evidence, affected packages and advisories. Costs one request of the monthly quota.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "severity": {
          "type": "string",
          "enum": [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
          ],
          "description": "Keep only this severity."
        },
        "limit": {
          "type": "integer",
          "minimum": 1,
          "maximum": 20,
          "description": "Number of CVEs to return (default 10, max 20)."
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "search_indicators",
    "title": "Find lookalike domains",
    "description": "Find the domains isMalicious lists that look like a brand or domain (e.g. \"paypal\", read as paypal.com, or \"login.paypal.com\"): typosquats, homoglyphs, the same name on other TLDs or hosting platforms, or wrapped in phishing words such as login or secure. The default API returns them most dangerous first, at most 500, with the searched name itself first when it is listed; other API bases can have different bounds. `total_hits` counts this API sample. `truncated: true` means results were omitted; `null` means completeness is unknown. An empty answer does not prove no lookalike exists: only listed domains are returned, and a name buried in a longer hostname is not matched. Follow up with check_indicator or check_indicators for verdicts. Cost: one request of the monthly quota, on the default https://ismalicious.com/api as on the Rust API host (https://api.ismalicious.com).",
    "inputSchema": {
      "type": "object",
      "properties": {
        "keywords": {
          "type": "string",
          "description": "Brand, domain or URL to find lookalikes of, e.g. paypal (read as paypal.com) or login.paypal.com.",
          "minLength": 2,
          "maxLength": 128
        },
        "limit": {
          "type": "integer",
          "minimum": 1,
          "maximum": 500,
          "description": "Maximum hits to keep from the API sample (default 50, max 500); this does not increase the backend search limit."
        }
      },
      "required": [
        "keywords"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "check_indicators",
    "title": "Check indicators in bulk",
    "description": "Reputation of up to 100 indicators in one call, for triaging a list rather than one alert: IPs, domains, URLs, file hashes (MD5, SHA-1 or SHA-256), email addresses and phone numbers, mixed freely; defanged input is accepted. Each row: malicious, recommendedAction (block, escalate, review, monitor, allow, unverified; unverified means nothing is known either way, and an email address or phone number is never allow), risk 0-100 with level, the number of threat blocklists citing it, categories, lookupStatus, and `infrastructure` (cloud, cdn, tor-exit…) when the entity is known as such. A row with `pending` (e.g. [\"circl\"] for a hash whose lookup outlasted the API's deadline) is not settled: re-check it once, after a few seconds. A URL row is judged on its host. BILLING: every unique indicator the API receives charges one request of the monthly quota — unique after trimming and lowercasing, and including rows the API cannot type, which come back with an error. Exact duplicates are free; entries under 3 characters, SHA-512, TLSH and ssdeep, and input that is none of the six kinds (an address or a number in a shape the API cannot read, a number written with letters, a host that is not a dotted domain name) are refused here with a per-row error, never sent and never charged. Plans cap the batch below the tool ceiling (Free 10, Basic 50, Pro 100); over the cap the API refuses the whole batch. Use check_indicator for the full picture of one indicator.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "indicators": {
          "type": "array",
          "items": {
            "type": "string",
            "minLength": 3,
            "maxLength": 2048
          },
          "minItems": 1,
          "maxItems": 100,
          "description": "The indicators to check, at most 100. Each unique one sent costs one request."
        },
        "enrichment": {
          "type": "string",
          "enum": [
            "basic",
            "standard",
            "full"
          ],
          "description": "\"standard\" (default) adds the risk score; \"basic\" is the verdict and blocklist count only and answers faster; \"full\" adds nothing visible in this projection."
        },
        "country": {
          "type": "string",
          "minLength": 2,
          "maxLength": 2,
          "description": "ISO 3166-1 alpha-2 country applied to every phone number written in national format (06 12 34 56 78 with FR). Numbers written with + or 00 ignore it."
        }
      },
      "required": [
        "indicators"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "scan_email",
    "title": "Scan an email for phishing and malware",
    "description": "Scan ONE email message for phishing and malware before delivering, opening or acting on it. Send the raw message (eml, preferred) or the fields you already parsed (message: headers, text, html, attachment names, types and digests). Returns a verdict (malicious | suspicious | clean | inconclusive), a recommendedAction (quarantine | review | warn | deliver), a 0-100 riskScore, a headline you can relay as is, the strongest reasons, and what it could not check (coverage.skipped). It reads the sender and Reply-To, the connecting server, every link host and every attachment hash against threat intelligence, plus the tells of a phishing message: link text that names another site, a domain or a display name that imitates a well-known brand, a program named like a document, a display name that shows another address, credentials in a URL, an IDN homograph. From a raw message it also reads attachments for structure, never running them: the file type from its bytes, macros and remote templates in Office files, risky entries in archives, PDF actions, HTML that rebuilds a file in the browser; a message attached to it is read as a message of its own. It also flags text aimed at an AI reading the mail (prompt injection, including text hidden from a person). It never runs an attachment, fetches a link or calls a third party while you wait. malicious needs a listing in our data: the shape of a message alone asks for a review at most. clean is a positive claim and needs your own receiving system's DMARC pass: pass authservId (the id it writes in its Authentication-Results header) or trustAuthenticationResults, otherwise a message with nothing against it is inconclusive, which is not safe. deliver means no objection from this scan; never use it to release a message another engine quarantined. Costs one scan of the scan meter per message, whatever its size (not a request of the monthly quota).",
    "inputSchema": {
      "type": "object",
      "properties": {
        "eml": {
          "type": "string",
          "description": "The whole message as RFC 5322 text (a .eml file), headers first. Up to 10 MiB. Preferred when you have it: attachments are then read for structure. Use message for one that is too large, or that you only have parsed. Send exactly one of eml and message.",
          "minLength": 1
        },
        "message": {
          "type": "object",
          "description": "A message you already parsed (Microsoft Graph, Gmail API…). Attachments carry digests, not bytes, so their structure is not read. Send exactly one of eml and message.",
          "properties": {
            "headers": {
              "type": "array",
              "description": "Every header, in message order, exactly as received (Graph: internetMessageHeaders). Needed for the Received chain (the server that delivered it) and Authentication-Results.",
              "items": {
                "type": "object",
                "properties": {
                  "name": {
                    "type": "string"
                  },
                  "value": {
                    "type": "string"
                  }
                },
                "required": [
                  "name",
                  "value"
                ]
              }
            },
            "from": {
              "type": "string",
              "description": "The sender, `Name <address>` or an address. Only needed when headers has no From."
            },
            "replyTo": {
              "type": "string",
              "description": "The Reply-To address."
            },
            "returnPath": {
              "type": "string",
              "description": "The Return-Path address."
            },
            "subject": {
              "type": "string"
            },
            "text": {
              "type": "string",
              "description": "The plain-text body."
            },
            "html": {
              "type": "string",
              "description": "The HTML body."
            },
            "attachments": {
              "type": "array",
              "description": "Attachments as metadata and digests; contents are not needed. Any of sha256, sha1 and md5 is enough; the more digests, the more of the dataset can answer.",
              "items": {
                "type": "object",
                "properties": {
                  "filename": {
                    "type": "string"
                  },
                  "contentType": {
                    "type": "string"
                  },
                  "size": {
                    "type": "integer",
                    "minimum": 0
                  },
                  "sha256": {
                    "type": "string"
                  },
                  "sha1": {
                    "type": "string"
                  },
                  "md5": {
                    "type": "string"
                  },
                  "inline": {
                    "type": "boolean",
                    "description": "True for a part shown inside the body. One with a picture's type and name is listed, not looked up; any other inline part is read like an attachment."
                  }
                }
              }
            }
          },
          "additionalProperties": false
        },
        "authservId": {
          "type": "string",
          "description": "The authserv-id your receiving system writes in its Authentication-Results header (for example mx.google.com). Only a header carrying it is read as SPF/DKIM/DMARC evidence, because anyone can write one into a message."
        },
        "trustAuthenticationResults": {
          "type": "boolean",
          "description": "True when every Authentication-Results header in the message was added by your own infrastructure (Exchange Online writes it with no authserv-id). Needed, with or instead of authservId, for a message to be clean."
        },
        "trustedHops": {
          "type": "integer",
          "minimum": 1,
          "maximum": 10,
          "description": "How many Received headers, counted from the top, your own servers wrote. The connecting server is the one the last of them recorded. Default 1."
        },
        "connectingIp": {
          "type": "string",
          "description": "The IP address that connected to your infrastructure, when you already have it. Overrides the Received chain."
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "exploited_cves",
    "title": "CVEs exploited in the wild",
    "description": "CVEs with attested exploitation in the last N days (default 7): confirmed (CISA KEV, CISA SSVC active, or two independent catalogues) or reported (one catalogue). Those first attested inside the window come first, then those only seen again in it; confirmed first in each. Each with severity, CVSS, EPSS, first and last exploitation evidence, KEV date, whether a patch exists, the sources, and how many indicators in our data were tagged with it this week (absent when unknown, never 0). Not in this list does not mean not exploited. Follow up with get_cve for one CVE. Costs one request of the monthly quota with a key; works without one (rate-limited by IP).",
    "inputSchema": {
      "type": "object",
      "properties": {
        "days": {
          "type": "integer",
          "minimum": 1,
          "maximum": 30,
          "description": "Window in days (default 7)."
        },
        "limit": {
          "type": "integer",
          "minimum": 1,
          "maximum": 50,
          "description": "Number of CVEs to return (default 20, max 50)."
        }
      },
      "additionalProperties": false
    }
  },
  {
    "name": "watch_domain",
    "title": "Watch a domain's stack for vulnerabilities",
    "description": "Start vulnerability monitoring of one public website: the API reads what the site exposes (Server and X-Powered-By headers, generator meta tag, versioned script paths, open ports) now and every day, matches each versioned component against CVEs, and alerts on what is exploited (P1 at once, P2/P3 in digests, per the organization's alert rules). Returns the source, the components read and the findings already open, with priority and fix. Uses one watched source of the plan (re-adding a watched domain returns the existing one and costs nothing). Only the public site is read; no scan beyond one page.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "domain": {
          "type": "string",
          "description": "Hostname to watch, e.g. shop.example.com (a URL is reduced to its host).",
          "maxLength": 2048
        },
        "name": {
          "type": "string",
          "description": "Optional display name for the source.",
          "maxLength": 120
        }
      },
      "required": [
        "domain"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "watch_dependencies",
    "title": "Watch a project's dependencies for vulnerabilities",
    "description": "Start vulnerability monitoring of a project from the text of its lockfile or SBOM: package-lock.json, composer.lock, requirements.txt, Gemfile.lock, Cargo.lock or a CycloneDX JSON SBOM (format detected when omitted). Each dependency is matched by version against OSV and NVD ranges; development dependencies are left out unless includeDev is true. Returns the source, the dependencies read (direct and transitive) and the findings already open, with priority and the version that fixes each. Uses one watched source of the plan; sending the same project name again replaces its file. Pass the file's content, not a path (at most 5 MiB).",
    "inputSchema": {
      "type": "object",
      "properties": {
        "content": {
          "type": "string",
          "description": "The lockfile or SBOM text.",
          "maxLength": 5242880
        },
        "name": {
          "type": "string",
          "description": "Project name shown in the stack, e.g. shop-frontend.",
          "maxLength": 120
        },
        "format": {
          "type": "string",
          "enum": [
            "package-lock.json",
            "composer.lock",
            "requirements.txt",
            "Gemfile.lock",
            "Cargo.lock",
            "cyclonedx.json"
          ],
          "description": "The file's format; detected from the content when omitted."
        },
        "includeDev": {
          "type": "boolean",
          "description": "Also watch development dependencies (default false)."
        }
      },
      "required": [
        "content",
        "name"
      ],
      "additionalProperties": false
    }
  },
  {
    "name": "ack_finding",
    "title": "Acknowledge a vulnerability finding",
    "description": "Set the status of one vulnerability-monitoring finding (an id like xfnd_…, from watch_domain, watch_dependencies or the Exposure page): ACKNOWLEDGED (seen, being handled), PATCHED (upgraded; the next read confirms it), NOT_AFFECTED (e.g. a distro backport fixed it), or SNOOZED until a date (at most 90 days; it reopens then). A finding reopens by itself when it enters CISA KEV or exploitation is reported. Changes nothing outside the caller's organization.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "findingId": {
          "type": "string",
          "description": "The finding's id (xfnd_…).",
          "maxLength": 64
        },
        "status": {
          "type": "string",
          "enum": [
            "ACKNOWLEDGED",
            "PATCHED",
            "NOT_AFFECTED",
            "SNOOZED"
          ],
          "description": "The new status."
        },
        "snoozedUntil": {
          "type": "string",
          "format": "date-time",
          "description": "Required with SNOOZED: when it reopens (ISO 8601, at most 90 days ahead)."
        }
      },
      "required": [
        "findingId",
        "status"
      ],
      "additionalProperties": false
    }
  }
];

export const TOOL_NAMES = TOOL_DEFS.map((t) => t.name);

/** Whether `name` belongs to the captured surface. */
export function isKnownTool(name: string): boolean {
  return TOOL_NAMES.includes(name);
}

/* ------------------------------------------------------------------ */
/* Forwarding client                                                   */
/* ------------------------------------------------------------------ */

function failureResult(detail: string): ToolResult {
  return {
    content: [{ type: "text", text: `threatcheck error: ${detail}` }],
    isError: true,
  };
}

function describeRpcError(error: unknown): string {
  if (error !== null && typeof error === "object") {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message !== "") return message;
    return JSON.stringify(error);
  }
  return String(error);
}

/**
 * Extract a JSON-RPC message from a response body that may
 * use SSE framing. Prefers the message whose id equals
 * `expectedId`; otherwise returns the last parseable message;
 * returns null when nothing in the body parses.
 */
export function parseRpcBody(
  text: string,
  expectedId?: number,
): Record<string, unknown> | null {
  const body = text.trim();
  if (body === "") return null;
  const messages: Record<string, unknown>[] = [];
  const collect = (raw: string): void => {
    try {
      const value: unknown = JSON.parse(raw);
      if (value !== null && typeof value === "object" && !Array.isArray(value)) {
        messages.push(value as Record<string, unknown>);
      }
    } catch {
      // Not JSON; this candidate is ignored.
    }
  };
  if (body.includes("data:")) {
    for (const line of body.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("data:")) continue;
      const payload = trimmed.slice("data:".length).trim();
      if (payload !== "" && payload !== "[DONE]") collect(payload);
    }
  } else {
    collect(body);
  }
  if (messages.length === 0) return null;
  if (expectedId !== undefined) {
    const hit = messages.find((m) => m.id === expectedId);
    if (hit !== undefined) return hit;
  }
  return messages[messages.length - 1];
}

async function globalFetch(
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
): Promise<FetchResponseLike> {
  return fetch(url, init) as unknown as FetchResponseLike;
}

/**
 * A forwarding client holding one upstream session, opened
 * lazily on first use and reused afterwards (for the process
 * life in the MCP server, or for a single run in the CLI).
 */
export class ThreatcheckClient {
  private readonly deps: ForwardDeps;
  private sessionId: string | null = null;
  private established = false;
  private opening: Promise<void> | null = null;
  private lastId = 0;

  constructor(deps: ForwardDeps = {}) {
    this.deps = deps;
  }

  private fetchFn(): FetchFn {
    return this.deps.fetchFn ?? globalFetch;
  }

  private endpointUrl(): string {
    if (this.deps.url && this.deps.url.trim() !== "") return this.deps.url.trim();
    const fromEnv = (this.deps.env ?? process.env).ISMALICIOUS_MCP_URL;
    if (fromEnv && fromEnv.trim() !== "") return fromEnv.trim();
    return DEFAULT_ENDPOINT_URL;
  }

  private apiKey(): string | null {
    const raw = (this.deps.env ?? process.env).ISMALICIOUS_API_KEY;
    if (raw && raw.trim() !== "") return raw.trim();
    return null;
  }

  private timeoutMs(): number {
    if (typeof this.deps.timeoutMs === "number" && this.deps.timeoutMs > 0) {
      return this.deps.timeoutMs;
    }
    return DEFAULT_TIMEOUT_MS;
  }

  private allocateId(): number {
    this.lastId += 1;
    return this.lastId;
  }

  private async send(
    payload: unknown,
    attachSession: boolean,
  ): Promise<FetchResponseLike> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    const key = this.apiKey();
    if (key !== null) headers["Authorization"] = `Bearer ${key}`;
    if (attachSession && this.sessionId !== null) {
      headers["Mcp-Session-Id"] = this.sessionId;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs());
    try {
      return await this.fetchFn()(this.endpointUrl(), {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  private async openSession(): Promise<void> {
    if (this.established) return;
    if (this.opening === null) {
      this.opening = (async () => {
        const initId = this.allocateId();
        const initRes = await this.send(
          {
            jsonrpc: "2.0",
            id: initId,
            method: "initialize",
            params: {
              protocolVersion: PROTOCOL_VERSION,
              capabilities: {},
              clientInfo: { name: "threatcheck", version: VERSION },
            },
          },
          false,
        );
        const issued = initRes.headers.get("mcp-session-id");
        if (issued) this.sessionId = issued;
        const initText = await initRes.text();
        const initMessage = parseRpcBody(initText, initId);
        if (initMessage !== null && initMessage.error) {
          throw new Error(describeRpcError(initMessage.error));
        }
        if (initRes.status < 200 || initRes.status >= 300) {
          throw new Error(`HTTP ${initRes.status}`);
        }
        if (initMessage === null && initText.trim() !== "") {
          throw new Error("malformed response");
        }
        const noteRes = await this.send(
          { jsonrpc: "2.0", method: "notifications/initialized" },
          true,
        );
        try {
          await noteRes.text();
        } catch {
          // The notification response body carries nothing we need.
        }
        this.established = true;
      })();
    }
    try {
      await this.opening;
    } catch (err) {
      this.opening = null;
      this.sessionId = null;
      throw err;
    }
  }

  /** Forward one tool call; upstream failures come back as isError results. */
  async callTool(name: string, args: ToolArgs): Promise<ToolResult> {
    try {
      await this.openSession();
    } catch (err) {
      return failureResult(err instanceof Error ? err.message : String(err));
    }

    const callId = this.allocateId();
    let callRes: FetchResponseLike;
    try {
      callRes = await this.send(
        {
          jsonrpc: "2.0",
          id: callId,
          method: "tools/call",
          params: { name, arguments: args ?? {} },
        },
        true,
      );
    } catch (err) {
      return failureResult(
        `request failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    const message = parseRpcBody(await callRes.text(), callId);
    if (message !== null && message.error) {
      return failureResult(describeRpcError(message.error));
    }
    if (callRes.status < 200 || callRes.status >= 300) {
      return failureResult(`HTTP ${callRes.status}`);
    }
    if (message === null) return failureResult("malformed response");
    const result = message.result as ToolResult | undefined;
    if (result === undefined || result === null || typeof result !== "object") {
      return failureResult("malformed response");
    }
    // The upstream result is returned exactly as it arrived.
    return result;
  }
}

/** Build a forwarding client; tests inject a fake fetch and env through deps. */
export function createClient(deps: ForwardDeps = {}): ThreatcheckClient {
  return new ThreatcheckClient(deps);
}

/** One-shot helper: a fresh client for a single call (the CLI path). */
export async function callTool(
  name: string,
  args: ToolArgs,
  deps: ForwardDeps = {},
): Promise<ToolResult> {
  return new ThreatcheckClient(deps).callTool(name, args);
}
