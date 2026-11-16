#!/usr/bin/env node
import * as fs from 'node:fs';
import * as readline from 'node:readline';
import { Command } from 'commander';
import { applySandboxFlags, createEngine, CommonCliOptions } from './bootstrap';
import { CliApprover } from './governance/approvers';
import { verifyAuditFile } from './governance/audit';
import { defaultPolicy, loadPolicy } from './governance/policy';
import { SelectingSandbox } from './sandbox/select';
import type { Sandbox } from './sandbox/types';
import { buildImage, cleanContainers, defaultImageTag, imageStatus, listSandboxContainers } from './sandbox/dockerImage';
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
    .option('--learn-skills', 'offer to save successful code as reusable skills (each save needs approval)')
    .option('--sandbox <mode>', 'isolation layer: auto (default) | container | process')
    .option('--require-container', 'generated code runs ONLY if the container layer passes its probe');

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
    console.log(`StarClaw ${VERSION} | sandbox probe OK (${boot.sandbox.results.length} checks); ${engine.sandbox.describe().split('. ')[0]} | memory: ${boot.memory.ok ? 'verified' : 'INTEGRITY PROBLEMS: ' + JSON.stringify(boot.memory.tampered.length + boot.memory.chainErrors.length)}`);
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

function printProbe(title: string, r: { results: Array<{ name: string; denied: boolean; detail: string }>; skipped: string[]; durationMs: number; nodeVersion: string; platform: string }) {
  console.log(`\n== ${title} (Node ${r.nodeVersion} on ${r.platform}; ${r.results.filter((i) => i.denied).length}/${r.results.length} checks passed in ${r.durationMs} ms)`);
  for (const i of r.results) console.log(`  [${i.denied ? ' ok ' : 'FAIL'}] ${i.name} -> ${i.detail.replace(/\s+/g, ' ').slice(0, 110)}`);
  for (const s of r.skipped) console.log(`  [skip] ${s}`);
}

program
  .command('doctor')
  .description('probe the isolation layers on this machine, print what is and is not blocked, and which layer is active and why')
  .option('--policy <file>', 'policy JSON file')
  .option('--workspace <dir>', 'workspace dir', 'workspace')
  .option('--sandbox <mode>', 'auto | container | process (overrides the policy)')
  .option('--require-container', 'refuse unless the container layer passes its probe')
  .action(async (o: CommonCliOptions) => {
    try {
      const policy = applySandboxFlags(loadPolicy(o.policy), o);
      const sb = new SelectingSandbox({
        mode: policy.sandbox.mode,
        requireContainer: policy.sandbox.requireContainer,
        workspaceDir: o.workspace ?? 'workspace',
        timeoutMs: policy.sandbox.timeoutSeconds * 1000,
        maxOutputBytes: policy.sandbox.maxOutputBytes,
        memoryMb: policy.sandbox.memoryMb,
        maxBrokerCalls: policy.sandbox.maxBrokerCalls,
        containerImage: policy.sandbox.containerImage,
        containerPidsLimit: policy.sandbox.containerPidsLimit,
        containerRuntime: policy.sandbox.containerRuntime,
      });
      const layers: Array<['container' | 'process', Sandbox]> = [['container', sb.container], ['process', sb.proc]];
      for (const [name, layer] of layers) {
        try {
          await layer.ensureSafe();
        } catch {
          /* reported from lastProbe below */
        }
        const r = layer.lastProbe;
        if (r) printProbe(`${name.toUpperCase()} layer probe: ${r.ok ? 'PASSED' : 'FAILED'}`, r);
        else console.log(`\n== ${name.toUpperCase()} layer: not probed`);
      }
      let ok = true;
      try {
        await sb.ensureSafe();
      } catch (e: any) {
        ok = false;
        console.log(`\n${e.message}`);
      }
      console.log(`\n${sb.describe()}`);
      console.log(ok ? 'Generated code MAY run.' : 'Generated code will NOT run: StarClaw refuses to execute it on this machine/configuration.');
      process.exit(ok ? 0 : 1);
    } catch (e) {
      fatal(e);
    }
  });

const sandboxCmd = program.command('sandbox').description('manage the Docker container layer');
sandboxCmd
  .command('build')
  .description('build the sandbox image from the packaged Dockerfile and runner')
  .option('--tag <tag>', 'image tag (default starclaw-sandbox:<version>)')
  .action(async (o: { tag?: string }) => {
    try {
      const tag = o.tag ?? defaultImageTag();
      console.log(`building ${tag} ...`);
      const code = await buildImage({ tag, onLog: (s) => process.stdout.write(s) });
      console.log(code === 0 ? `built ${tag}` : `docker build failed (exit ${code})`);
      process.exit(code);
    } catch (e) {
      fatal(e);
    }
  });
sandboxCmd
  .command('status')
  .description('show Docker availability, image state and sandbox containers')
  .option('--tag <tag>', 'image tag')
  .action(async (o: { tag?: string }) => {
    const st = await imageStatus({ tag: o.tag });
    console.log(`docker: ${st.dockerOk ? 'available (server ' + st.dockerVersion + ')' : 'NOT available'}`);
    console.log(`image ${st.tag}: ${st.imagePresent ? 'present (' + (st.imageId ?? '').slice(0, 19) + ')' : 'missing'}; ${st.detail}`);
    const running = st.dockerOk ? await listSandboxContainers() : [];
    console.log(`sandbox containers on this host (label starclaw.sandbox=1): ${running.length}${running.length ? ' -> ' + running.join(', ') : ''}`);
    const usable = st.dockerOk && st.imagePresent && st.runnerMatches;
    console.log(`container layer usable: ${usable ? 'yes, subject to the probe that runs before first use (see: starclaw doctor)' : 'no'}`);
    process.exit(usable ? 0 : 1);
  });
sandboxCmd
  .command('clean')
  .description('remove sandbox containers (only those labelled starclaw.sandbox=1 with the starclaw-sbx- name prefix)')
  .action(async () => {
    const removed = await cleanContainers();
    console.log(removed.length ? `removed: ${removed.join(', ')}` : 'nothing to remove');
  });

program.parseAsync(process.argv).catch(fatal);
