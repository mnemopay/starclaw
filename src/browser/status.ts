import type { Policy } from '../governance/policy';
import { ControlClient, ControlError, defaultDiscoveryPath, readDiscovery } from './control';

export interface BrowserStatus {
  enabled: boolean;
  /** One human line for `starclaw doctor`. Never contains the token. */
  line: string;
  warnings: string[];
}

/**
 * Host-side diagnostic for `starclaw doctor`: policy state, discovery file, and (only when the policy enables the
 * browser) one GET /v1/health. This is an operator check, not an agent action, so it is not routed through the Governor.
 */
export async function browserStatus(policy: Policy, discoveryPath: string = defaultDiscoveryPath()): Promise<BrowserStatus> {
  const b = policy.browser;
  if (!b.enabled) return { enabled: false, line: 'Browser: disabled (policy browser.enabled = false; tools.browse* refuse)', warnings: [] };
  const typing = b.allowInput ? `typing ALLOWED (browser.type is "${policy.defaults['browser.type']}")` : 'typing off (browser.allowInput = false)';
  const base = `Browser: enabled; ${b.allowedDomains.length} allowed domain(s), maxActions ${b.maxActions}, budget ${b.budgetCents}c, ttl ${b.ttlSeconds}s, click "${policy.defaults['browser.click']}", ${typing}`;
  const warnings: string[] = [];
  if (b.allowInput && policy.defaults['browser.type'] === 'allow') warnings.push('defaults["browser.type"] is "allow": in a clean, attended session the model can type into pages without asking you (a tainted session or an unattended run still must ask)');
  try {
    const d = readDiscovery(discoveryPath);
    const client = new ControlClient(d, { timeoutMs: 5000 });
    const h = await client.health();
    const did = h && typeof h.did === 'string' ? ` DID ${client.scrub(h.did).slice(0, 80)}` : '';
    return { enabled: true, line: `${base}; control API reachable at ${new URL(d.url).host}${did}`, warnings };
  } catch (e) {
    const why = e instanceof ControlError ? e.message : 'unexpected error';
    return { enabled: true, line: `${base}; control API NOT available: ${why}`, warnings: [...warnings, 'tools.browse* will fail closed until the browser runs with MNEMOPAY_CONTROL_API=1'] };
  }
}
