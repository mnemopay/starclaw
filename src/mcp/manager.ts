import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { getDefaultEnvironment, StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { McpServerConfig } from '../governance/policy';

/**
 * Connections to the MCP servers the OWNER declared in the policy (the agent can never add one).
 *
 * - stdio servers are programs on this PC, started with a minimal environment: the SDK's safe defaults (PATH, HOME...)
 *   plus only the variable NAMES listed in the policy. Your other secrets (model keys, tokens) are not inherited.
 *   They run outside StarClaw's sandbox: only declare servers you trust as you would any installed program.
 * - http servers must be https (http only to this PC); an optional bearer token comes from a named env var.
 * Everything a server says (tool descriptions included) is untrusted; the broker taints the session on use.
 */

export interface McpToolInfo { name: string; description: string; inputSchema: unknown }

const CLIENT_INFO = { name: 'starclaw', version: '2' };
const MAX_TOOLS = 200;
const MAX_DESC = 1000;

export class McpManager {
  private clients = new Map<string, Promise<Client>>();
  private tools = new Map<string, McpToolInfo[]>();

  constructor(private readonly servers: readonly McpServerConfig[], private readonly opts: { cwd: string; env?: NodeJS.ProcessEnv } = { cwd: process.cwd() }) {}

  config(name: string): McpServerConfig | undefined {
    return this.servers.find((s) => s.name === name);
  }
  get serverNames(): string[] {
    return this.servers.map((s) => s.name);
  }

  private connect(s: McpServerConfig): Promise<Client> {
    let p = this.clients.get(s.name);
    if (!p) {
      p = (async () => {
        const env = this.opts.env ?? process.env;
        const client = new Client(CLIENT_INFO);
        if (s.transport === 'stdio') {
          const childEnv: Record<string, string> = { ...getDefaultEnvironment() };
          for (const n of s.env) if (env[n] !== undefined) childEnv[n] = env[n]!;
          await client.connect(new StdioClientTransport({ command: s.command!, args: s.args, env: childEnv, cwd: this.opts.cwd, stderr: 'ignore' }), { timeout: s.timeoutSeconds * 1000 });
        } else {
          const headers: Record<string, string> = {};
          if (s.bearerTokenEnv) {
            const t = env[s.bearerTokenEnv];
            if (!t) throw new Error(`MCP server ${s.name}: environment variable ${s.bearerTokenEnv} is not set`);
            headers.authorization = `Bearer ${t}`;
          }
          await client.connect(new StreamableHTTPClientTransport(new URL(s.url!), { requestInit: { headers, redirect: 'error' } }), { timeout: s.timeoutSeconds * 1000 });
        }
        return client;
      })();
      // A failed start is not cached: the next call tries again.
      p.catch(() => this.clients.delete(s.name));
      this.clients.set(s.name, p);
    }
    return p;
  }

  /** The server's tools, filtered by the policy allow-list (if any). Cached per connection. */
  async listTools(name: string): Promise<McpToolInfo[]> {
    const s = this.config(name);
    if (!s) throw new Error(`no MCP server named ${name} in the policy`);
    const cached = this.tools.get(name);
    if (cached) return cached;
    const client = await this.connect(s);
    const out: McpToolInfo[] = [];
    let cursor: string | undefined;
    do {
      const r = await client.listTools(cursor ? { cursor } : undefined, { timeout: s.timeoutSeconds * 1000 });
      for (const t of r.tools) {
        if (s.tools && !s.tools.includes(t.name)) continue;
        out.push({ name: t.name, description: String(t.description ?? '').slice(0, MAX_DESC), inputSchema: t.inputSchema });
        if (out.length >= MAX_TOOLS) break;
      }
      cursor = out.length < MAX_TOOLS ? r.nextCursor : undefined;
    } while (cursor);
    this.tools.set(name, out);
    return out;
  }

  /** Call a tool. Returns bounded text + structured content; never throws the server's raw payload beyond the cap. */
  async callTool(name: string, tool: string, args: Record<string, unknown>): Promise<{ isError: boolean; text: string; structured?: unknown; nonText: number; truncated: boolean }> {
    const s = this.config(name)!;
    const client = await this.connect(s);
    const r: any = await client.callTool({ name: tool, arguments: args }, undefined, { timeout: s.timeoutSeconds * 1000 });
    const parts: any[] = Array.isArray(r?.content) ? r.content : [];
    let text = parts.filter((c) => c?.type === 'text' && typeof c.text === 'string').map((c) => c.text).join('\n');
    const nonText = parts.filter((c) => c?.type !== 'text').length;
    let truncated = false;
    if (text.length > s.maxResultChars) {
      text = text.slice(0, s.maxResultChars);
      truncated = true;
    }
    let structured: unknown;
    if (r?.structuredContent !== undefined) {
      const j = JSON.stringify(r.structuredContent);
      if (j.length <= s.maxResultChars) structured = r.structuredContent;
      else truncated = true;
    }
    return { isError: r?.isError === true, text, structured, nonText, truncated };
  }

  async close(): Promise<void> {
    const all = [...this.clients.values()];
    this.clients.clear();
    this.tools.clear();
    await Promise.all(all.map((p) => p.then((c) => c.close()).catch(() => {})));
  }
}
