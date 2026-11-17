import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AuditLog } from '../../governance/audit';
import type { Policy } from '../../governance/policy';
import { Ed25519Signer } from '../../governance/signer';
import { SkillRegistry } from './registry';

/**
 * The `starclaw doctor` line. READ-ONLY: it never creates a key or state and never writes an audit record
 * (status() does not append). When the registry is disabled it touches nothing on disk.
 */
export function skillsRegistryStatus(policy: Policy, stateDir: string): { line: string; warnings: string[] } {
  if (!policy.skillsRegistry.enabled) return { line: 'Skills registry: disabled (policy skillsRegistry.enabled = false)', warnings: [] };
  const dir = path.resolve(stateDir);
  if (!fs.existsSync(path.join(dir, 'audit.key'))) {
    return { line: 'Skills registry: enabled; no state yet; local files only, no network fetch', warnings: ['no publisher keys are pinned: nothing can be installed (starclaw skills keys add)'] };
  }
  const reg = new SkillRegistry({
    dir: path.join(dir, 'skills-registry'),
    signer: Ed25519Signer.loadOrCreate(dir),
    audit: { append() {} } as unknown as AuditLog,
    policy: () => policy.skillsRegistry,
    authorize: async () => {
      throw new Error('status is read-only');
    },
  });
  return reg.status();
}
