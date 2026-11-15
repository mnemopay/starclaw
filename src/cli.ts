#!/usr/bin/env node
import * as fs from 'node:fs';
import * as readline from 'node:readline';
import { Command } from 'commander';
import { createEngine, CommonCliOptions } from './bootstrap';
import { CliApprover } from './governance/approvers';
import { verifyAuditFile } from './governance/audit';
import { defaultPolicy, loadPolicy } from './governance/policy';
import { ProcessSandbox } from './sandbox/ProcessSandbox';
import { StarClawEngine } from './engine';

const VERSION: string = (() => {
  try {
    return JSON.parse(fs.readFileSync(require.resolve('../package.json'), 'utf8')).version;
  } catch {
    return '0.0.0';
  }
})();

const program = new Command();
program
  .name('starclaw')
  .description('A governed autonomous agent: every action is policy-checked, approval-gated, spend-capped and audit-logged.')
  .version(VERSION);

const common = (c: Command) =>
  c
    .option('--policy <file>', 'policy JSON file (default: ./starclaw.policy.json if present, else built-in conservative defaults)')
    .option('--state-dir <dir>', 'where keys, audit log and memory live (default ./.starclaw)')
    .option('--workspace <dir>', 'workspace directory the agent may write to (default from policy: ./workspace)')
    .option('--learn-skills', 'offer to save successful code as reusable skills (each save needs approval)');

function fatal(e: any): never {
  console.error(`starclaw: ${e?.message ?? e}`);
  process.exit(1);
}

async function runGoalOnce(engine: StarClawEngine, goal: string, jsonOut: boolean) {
  await engine.boot();
  const r = await engine.executeGoal(goal, { onLog: (m) => console.error(`[starclaw] ${m}`) });
  if (jsonOut) console.log(JSON.stringify(r, null, 2));
  else {
    if (r.stdout) console.log(r.stdout.trimEnd());
    if (r.reply) console.log(r.reply);
    if (r.result !== undefined && r.result !== null) console.log(typeof r.result === 'string' ? r.result : JSON.stringify(r.result, null, 2));
    if (!r.success) console.error(`starclaw: failed: ${r.error}`);
  }
  process.exitCode = r.success ? 0 : 1;
}

common(program.command('run <goal>').description('run a single goal and exit'))
  .option('--non-interactive', 'no approver: every action the policy does not auto-allow is DENIED')
  .option('--json', 'print the full result as JSON')
  .action(async (goal: string, o: CommonCliOptions & { nonInteractive?: boolean; json?: boolean }) => {
    try {
      let rl: readline.Interface | undefined;
      let approver: CliApprover | undefined;
      if (!o.nonInteractive && process.stdin.isTTY) {
        rl = readline.createInterface({ input: process.stdin, output: process.stderr });
        approver = new CliApprover(
          (prompt, signal) => new Promise((res, rej) => { signal.addEventListener('abort', () => rej(new Error('timeout'))); rl!.question(prompt, { signal }, res); }),
          (s) => console.error(s),
        );
      } else if (!o.nonInteractive) {
        console.error('starclaw: stdin is not a terminal, so no one can approve actions: running non-interactively (everything not auto-allowed by policy is denied).');
      }
      const engine = createEngine(o, approver);
      await runGoalOnce(engine, goal, !!o.json);
      rl?.close();
    } catch (e) {
      fatal(e);
    }
  });

common(program.command('interactive', { isDefault: true }).description('interactive session (default)')).action(async (o: CommonCliOptions) => {
  try {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'starclaw> ' });
    const approver = new CliApprover(
      (prompt, signal) => new Promise((res, rej) => { signal.addEventListener('abort', () => rej(new Error('timeout'))); rl.question(prompt, { signal }, res); }),
    );
    const engine = createEngine(o, approver);
    const boot = await engine.boot();
    console.log(`StarClaw ${VERSION} | sandbox probe OK on Node ${boot.sandbox.nodeVersion} (${boot.sandbox.results.length} checks) | memory: ${boot.memory.ok ? 'verified' : 'INTEGRITY PROBLEMS: ' + JSON.stringify(boot.memory.tampered.length + boot.memory.chainErrors.length)}`);
    console.log("Commands: /new (fresh session, clears taint), /status, exit. Every action not auto-allowed by policy asks you first.\n");
    rl.prompt();
    let busy = false;
    rl.on('line', async (line) => {
      if (busy) return; // a pending question() consumes the line itself
      const goal = line.trim();
      if (['exit', 'quit'].includes(goal.toLowerCase())) return rl.close();
      if (goal === '/new') { engine.newSession(); console.log('New session started (taint cleared).'); return rl.prompt(); }
      if (goal === '/status') { console.log(`tainted: ${engine.tainted}; audit records: ${engine.audit.length}; LLM spend this run: ${engine.budget.runCentsCeil}c, today: ${engine.budget.dayCentsCeil}c`); return rl.prompt(); }
      if (goal) {
        busy = true;
        try {
          const r = await engine.executeGoal(goal, { onLog: (m) => console.log(`  ${m}`) });
          if (r.stdout) console.log(r.stdout.trimEnd());
          if (r.reply) console.log(r.reply);
          if (r.result !== undefined && r.result !== null) console.log(typeof r.result === 'string' ? r.result : JSON.stringify(r.result, null, 2));
          console.log(r.success ? (r.tainted ? '[done; session is TAINTED]' : '[done]') : `[failed] ${r.error}`);
        } catch (e: any) {
          console.error(`[error] ${e.message}`);
        }
        busy = false;
      }
      rl.prompt();
    }).on('close', () => process.exit(0));
  } catch (e) {
    fatal(e);
  }
});

const audit = program.command('audit').description('audit log tools');
audit
  .command('verify <file>')
  .description('verify hash chain, signatures and head checkpoint of an audit log, offline')
  .option('--pubkey <hex>', 'trusted Ed25519 public key (hex). Without it the key inside the log is trusted, which cannot rule out a fully re-signed log')
  .option('--pubkey-file <file>', 'file containing the trusted public key (e.g. .starclaw/audit.pub kept elsewhere)')
  .option('--allow-missing-head', 'do not fail if the .head checkpoint is missing (tail truncation then cannot be detected)')
  .option('--json', 'machine-readable output')
  .action((file: string, o: { pubkey?: string; pubkeyFile?: string; allowMissingHead?: boolean; json?: boolean }) => {
    const pub = o.pubkey ?? (o.pubkeyFile ? fs.readFileSync(o.pubkeyFile, 'utf8').trim() : undefined);
    const r = verifyAuditFile(file, { pinnedPublicKeyHex: pub, allowMissingHead: o.allowMissingHead });
    if (o.json) console.log(JSON.stringify(r, null, 2));
    else {
      console.log(r.ok ? `OK: ${r.records} records verified (chain, signatures${r.headChecked ? ', head checkpoint' : ''}); key ${r.keyPinned ? 'pinned' : 'taken from log'}` : `FAILED: ${r.errors.length} problem(s)`);
      for (const e of r.errors) console.log(`  line ${e.line}: ${e.reason}`);
      for (const w of r.warnings) console.log(`  warning: ${w}`);
    }
    process.exit(r.ok ? 0 : 1);
  });

const policy = program.command('policy').description('policy file tools');
policy
  .command('init [file]')
  .description('write the conservative default policy to a file')
  .action((file = 'starclaw.policy.json') => {
    if (fs.existsSync(file)) fatal(`${file} already exists`);
    fs.writeFileSync(file, JSON.stringify(defaultPolicy(), null, 2) + '\n');
    console.log(`wrote ${file}`);
  });
policy
  .command('check [file]')
  .description('validate a policy file (exit 1 if invalid)')
  .action((file?: string) => {
    try {
      const p = loadPolicy(file);
      console.log('policy OK');
      console.log(JSON.stringify(p.defaults));
    } catch (e: any) {
      console.error(e.message);
      process.exit(1);
    }
  });

program
  .command('doctor')
  .description('run the sandbox probe on this machine and print exactly what is and is not blocked')
  .option('--workspace <dir>', 'workspace dir', 'workspace')
  .action(async (o: { workspace: string }) => {
    const sb = new ProcessSandbox({ workspaceDir: o.workspace });
    let ok = true;
    try {
      await sb.ensureSafe();
    } catch {
      ok = false;
    }
    const r = sb.lastProbe!;
    console.log(`Node ${r.nodeVersion} on ${r.platform}; probe took ${r.durationMs} ms`);
    for (const i of r.results) console.log(`  [${i.denied ? ' ok ' : 'FAIL'}] ${i.name} -> ${i.detail.replace(/\s+/g, ' ').slice(0, 110)}`);
    for (const s of r.skipped) console.log(`  [skip] ${s}`);
    console.log(ok ? '\nSandbox is AVAILABLE: generated code may run.' : '\nSandbox is UNAVAILABLE: StarClaw will refuse to run generated code on this Node build.');
    process.exit(ok ? 0 : 1);
  });

program.parseAsync(process.argv).catch(fatal);
