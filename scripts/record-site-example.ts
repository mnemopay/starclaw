/** Record the public website example using the real engine and a scripted model/approver. No API calls or money. */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { StarClawEngine } from '../src/engine';
import { parsePolicy } from '../src/governance/policy';
import { Ed25519Signer } from '../src/governance/signer';
import { verifyAuditFile } from '../src/governance/audit';
import type { LLM } from '../src/llm/types';
import type { ApprovalRequest } from '../src/governance/types';

const goal = 'Read launch-notes.txt and save the product facts as launch-brief.md.';
const input = `StarClaw launch notes\n\n- Open-source agent for research, code changes, and scheduled work.\n- Actions pass through a policy that can allow, ask, or deny.\n- Audit records are signed and hash-chained.\n- Developer alpha. Does not prevent prompt injection.\n`;
const code = `async function execute() {
  const notes = await tools.readFile({ path: 'launch-notes.txt' });
  const facts = notes.content.split('\\n').filter(line => line.startsWith('- '));
  const content = '# StarClaw / launch brief\\n\\n' + facts.join('\\n') + '\\n';
  await tools.writeFile({ path: 'launch-brief.md', content });
  return { file: 'launch-brief.md', facts: facts.length };
}
module.exports = { execute };`;
const response = <T>(value: T) => ({ value, usage: { inputTokens: 0, outputTokens: 0 }, price: { inputCentsPerMTok: 0, outputCentsPerMTok: 0 } });
const llm: LLM = {
  classifyIntent: async () => response('task' as const),
  generateCode: async () => response(code),
  converse: async () => response(''),
  fixCode: async () => response(code),
};

async function main() {
  // A non-user-specific path keeps usernames and private project paths out of the published audit.
  const parent = process.platform === 'win32' ? path.parse(process.cwd()).root : os.tmpdir();
  const root = fs.mkdtempSync(path.join(parent, 'starclaw-public-example-'));
  const signer = Ed25519Signer.generate();
  const runs: Record<string, unknown> = {};
  try {
    for (const answer of ['approve', 'deny'] as const) {
      const workspace = path.join(root, answer, 'workspace');
      const state = path.join(root, answer, 'state');
      fs.mkdirSync(workspace, { recursive: true });
      fs.writeFileSync(path.join(workspace, 'launch-notes.txt'), input);
      const approvals: ApprovalRequest[] = [];
      const engine = new StarClawEngine({
        llm, signer, workspaceDir: workspace, stateDir: state,
        policy: parsePolicy(JSON.stringify({ version: 1, sandbox: { mode: 'process' }, defaults: { 'memory.write': 'deny', 'skill.save': 'deny' } })),
        approver: { name: 'website-scripted-approver', request: async request => { approvals.push(request); return request.action.class === 'fs.write' ? answer : 'approve'; } },
      });
      try {
        await engine.boot();
        const result = await engine.executeGoal(goal);
        const verification = verifyAuditFile(path.join(state, 'audit.jsonl'), { pinnedPublicKeyHex: signer.publicKeyHex });
        if (!verification.ok || result.success !== (answer === 'approve')) throw new Error('Example did not match the recorded decision');
        const file = path.join(workspace, 'launch-brief.md');
        if (fs.existsSync(file) !== (answer === 'approve')) throw new Error('Write result does not match approval');
        runs[answer] = {
          result,
          approval: approvals.find(request => request.action.class === 'fs.write'),
          output: fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null,
          records: fs.readFileSync(path.join(state, 'audit.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line)),
          head: JSON.parse(fs.readFileSync(path.join(state, 'audit.jsonl.head'), 'utf8')),
        };
      } finally { engine.memory.close(); }
    }
    const output = path.resolve('site/editorial/example-run.json');
    fs.writeFileSync(output, JSON.stringify({ format: 1, provenance: 'Real StarClaw engine, scripted model and approver. Process permission sandbox. No network or real payments.', publicKey: signer.publicKeyHex, goal, input, code, runs }, null, 2) + '\n');
    console.log('Recorded both decisions and verified their signatures:', output);
  } finally {
    const expectedParent = path.resolve(parent);
    if (path.dirname(path.resolve(root)) !== expectedParent || !path.basename(root).startsWith('starclaw-public-example-')) throw new Error('Refusing unexpected cleanup path');
    fs.rmSync(root, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
