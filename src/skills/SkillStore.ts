import * as fs from 'node:fs';
import * as path from 'node:path';
import { sha256Hex } from '../governance/canonical';

const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,59}$/;

export function sanitizeSkillName(raw: string): string {
  const n = raw.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return NAME_RE.test(n) ? n : `skill-${Date.now()}`;
}

/**
 * Stores skills (previously-successful generated code) as plain files. Saving is NOT done here: callers must go
 * through the Governor (`skill.save`). Loading requires the expected SHA-256 (recorded in the signed memory row),
 * so a file edited on disk after it was approved is refused instead of executed.
 */
export class SkillStore {
  constructor(private readonly dir: string) {
    fs.mkdirSync(dir, { recursive: true });
  }

  save(name: string, code: string): { name: string; sha256: string } {
    const clean = sanitizeSkillName(name);
    fs.writeFileSync(path.join(this.dir, `${clean}.js`), code, 'utf8');
    return { name: clean, sha256: sha256Hex(code) };
  }

  load(name: string, expectedSha256: string): string {
    if (!NAME_RE.test(name)) throw new Error('invalid skill name');
    const file = path.join(this.dir, `${name}.js`);
    const code = fs.readFileSync(file, 'utf8');
    if (sha256Hex(code) !== expectedSha256) throw new Error(`skill ${name} was modified after it was approved (hash mismatch); refusing to run it`);
    return code;
  }
}
