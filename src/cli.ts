#!/usr/bin/env node
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { Command } from 'commander';
import * as dotenv from 'dotenv';
import { defaultAppHome, prepareAppHome, startApp } from './app';
import { applySandboxFlags, createEngine, CommonCliOptions } from './bootstrap';
import { HttpApprover } from './channels/http';
import { CliApprover } from './governance/approvers';
import { verifyAuditFile } from './governance/audit';
import { exportArticle12 } from './governance/article12';
import { serializeChainBundle } from './governance/chainBundle';
import { defaultPolicy, loadPolicy } from './governance/policy';
import { subagentsStatus } from './governance/subagent';
import { describeLlm } from './llm/factory';
import { LlmError } from './llm/http';
import { SelectingSandbox } from './sandbox/select';
import type { Sandbox } from './sandbox/types';
import { buildImage, cleanContainers, defaultImageTag, imageStatus, listSandboxContainers } from './sandbox/dockerImage';
import { StarClawEngine } from './engine';
import { runDaemon } from './daemon';
import { browserStatus } from './browser/status';
import { discordStatus, emailStatus, listenerStatus, signalStatus, slackStatus, whatsappStatus } from './channels/status';
import { resolveDiscordConfig } from './channels/config';
import { FetchDiscordApi, registerDiscordCommand } from './channels/discord';
import { Ed25519Signer, fingerprint } from './governance/signer';
import { buildBundle } from './skills/registry/bundle';
import { describeCaps } from './skills/registry/registry';
import { skillsRegistryStatus } from './skills/registry/status';
import { buildShellImage, cleanShellContainers, defaultShellImageTag, listShellContainers, shellImageStatus } from './shell/shellImage';

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

/** A missing key or model for the configured provider (the case guided setup fixes). */
function isModelConfigError(e: any): boolean {
  return (e instanceof LlmError && e.kind === 'config') || /^GROQ_API_KEY is not set/.test(String(e?.message));
}

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
audit
  .command('export <file>')
  .description('verify the log, then write an EU AI Act Article 12 bundle (MnemoPay format: mission.json, events.json/.csv, chain.txt, manifest.json) plus chain-bundle.json (MnemoPay AuditChain ChainBundle v1, for verifyBundle and on-chain anchoring). Refuses a log that does not verify.')
  .requiredOption('--out <dir>', 'output directory (created; existing bundle files are never overwritten)')
  .option('--pubkey <hex>', 'trusted Ed25519 public key (hex)')
  .option('--pubkey-file <file>', 'file containing the trusted public key')
  .option('--allow-missing-head', 'do not fail if the .head checkpoint is missing')
  .option('--operator <id>', 'operator identifier recorded in mission.json (the company that deployed the agent)')
  .option('--retention-months <n>', 'retention period stated in the bundle (Article 12 minimum: 6)', '6')
  .option('--budget-usd <n>', 'budget cap to state in mission.json (the log does not record it)')
  .action((file: string, o: { out: string; pubkey?: string; pubkeyFile?: string; allowMissingHead?: boolean; operator?: string; retentionMonths: string; budgetUsd?: string }) => {
    try {
      const retentionMonths = Number(o.retentionMonths);
      if (!Number.isInteger(retentionMonths) || retentionMonths < 6) throw new Error('--retention-months must be an integer of at least 6');
      const budgetMaxUsd = o.budgetUsd === undefined ? undefined : Number(o.budgetUsd);
      if (budgetMaxUsd !== undefined && !(budgetMaxUsd >= 0)) throw new Error('--budget-usd must be a non-negative number');
      const pub = o.pubkey ?? (o.pubkeyFile ? fs.readFileSync(o.pubkeyFile, 'utf8').trim() : undefined);
      const r = exportArticle12(file, { pinnedPublicKeyHex: pub, allowMissingHead: o.allowMissingHead, operatorId: o.operator, retentionMonths, budgetMaxUsd });
      fs.mkdirSync(o.out, { recursive: true });
      for (const f of r.bundle.files) fs.writeFileSync(path.join(o.out, f.path), f.body, { flag: 'wx' });
      const chainJson = serializeChainBundle(r.chainBundle);
      fs.writeFileSync(path.join(o.out, 'chain-bundle.json'), chainJson, { flag: 'wx' });
      console.log(`exported ${r.events} events to ${o.out} (log verified; key ${r.verification.keyPinned ? 'pinned' : 'taken from log'})`);
      console.log(`bundle sha256 ${r.bundle.bundleSha256}`);
      console.log(`chain-bundle.json (MnemoPay ChainBundle v1) merkle_root ${r.chainBundle.merkle_root}`);
      console.log(`chain-bundle.json sha256 ${createHash('sha256').update(chainJson).digest('hex')}`);
      for (const w of r.verification.warnings) console.log(`  warning: ${w}`);
    } catch (e) {
      fatal(e);
    }
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
  .option('--state-dir <dir>', 'state directory (only used for the skills registry line)')
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
      const ld = describeLlm(policy.llm);
      console.log(`Model: ${ld.provider} / ${ld.model}; key env ${ld.keyEnv}: ${ld.keyPresent ? 'set' : 'NOT set'}; price: ${ld.priceStatus}`);
      for (const w of ld.warnings) console.log(`  WARNING: ${w}`);
      const sp = policy.search;
      console.log(`Search: ${sp.provider}${sp.provider === 'searxng' ? ' (' + (sp.searxngUrl ?? 'no searxngUrl set') + ')' : ''}${sp.provider === 'brave' ? '; key env ' + (sp.apiKeyEnv ?? 'BRAVE_API_KEY') + ': ' + (process.env[sp.apiKeyEnv ?? 'BRAVE_API_KEY'] ? 'set' : 'NOT set') : ''}`);
      const bs = await browserStatus(policy);
      console.log(bs.line);
      for (const w of bs.warnings) console.log('  WARNING: ' + w);
      const sr = skillsRegistryStatus(policy, o.stateDir ?? process.env.STARCLAW_STATE_DIR ?? '.starclaw');
      console.log(sr.line);
      for (const w of sr.warnings) console.log('  WARNING: ' + w);
      let channelsBroken = false;
      for (const cs of [slackStatus(policy, process.env), discordStatus(policy, process.env), whatsappStatus(policy, process.env), signalStatus(policy, process.env), emailStatus(policy, process.env), listenerStatus(policy)]) {
        console.log(cs.line);
        for (const w of cs.warnings) console.log('  WARNING: ' + w);
        channelsBroken = channelsBroken || cs.broken;
      }
      if (channelsBroken) console.log('  A channel is enabled but misconfigured: `starclaw daemon` will refuse to start until that is fixed.');
      const ss = subagentsStatus(policy);
      console.log(ss.line);
      for (const w of ss.warnings) console.log('  WARNING: ' + w);
      const mcp = policy.mcp;
      console.log(`MCP: ${!mcp.enabled ? 'disabled' : mcp.servers.length ? `${mcp.servers.length} server(s): ${mcp.servers.map((s) => `${s.name} (${s.transport}${s.tools ? `, ${s.tools.length} allow-listed tools` : ', all tools'})`).join(', ')}; calls: ${policy.defaults['mcp.call']} by default` : 'enabled but no servers declared'}`);
      if (mcp.enabled && mcp.servers.some((s) => s.transport === 'stdio')) console.log('  NOTE: stdio MCP servers are programs on this PC and run OUTSIDE the sandbox; declare only ones you trust.');
      if (mcp.enabled && policy.defaults['mcp.call'] === 'allow') console.log('  WARNING: defaults["mcp.call"] is allow: any declared tool may run without asking in a clean session (tainted sessions still ask).');
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

// ---- shell container ---------------------------------------------------------------------------------------------

const shellCmd = program.command('shell').description('manage the governed shell container (tools.shell)');
shellCmd
  .command('build')
  .description('build the shell image from the packaged Dockerfile (the build may use the network; the running container never does)')
  .option('--tag <tag>', 'image tag (default starclaw-shell:<version>)')
  .action(async (o: { tag?: string }) => {
    try {
      const tag = o.tag ?? defaultShellImageTag();
      console.log(`building ${tag} ...`);
      const code = await buildShellImage({ tag, onLog: (s) => process.stdout.write(s) });
      console.log(code === 0 ? `built ${tag}` : `docker build failed (exit ${code})`);
      process.exit(code);
    } catch (e) {
      fatal(e);
    }
  });
shellCmd
  .command('status')
  .description('show Docker availability, shell image state and shell containers')
  .option('--tag <tag>', 'image tag')
  .action(async (o: { tag?: string }) => {
    const st = await shellImageStatus({ tag: o.tag });
    console.log(`docker: ${st.dockerOk ? 'available' : 'NOT available'}`);
    console.log(`image ${st.tag}: ${st.imagePresent ? 'present' : 'missing'}; ${st.detail}`);
    const running = st.dockerOk ? await listShellContainers() : [];
    console.log(`shell containers on this host (label starclaw.shell=1): ${running.length}${running.length ? ' -> ' + running.join(', ') : ''}`);
    process.exit(st.dockerOk && st.imagePresent && st.matches ? 0 : 1);
  });
shellCmd
  .command('clean')
  .description('remove shell containers (only those labelled starclaw.shell=1 whose names start with starclaw-sh-)')
  .action(async () => {
    const removed = await cleanShellContainers();
    console.log(removed.length ? `removed: ${removed.join(', ')}` : 'nothing to remove');
  });

// ---- scheduler ------------------------------------------------------------------------------------------------------

const noLlm = { llm: { classifyIntent: async () => { throw new Error('no model in this command'); } } as any };
const withJobs = (o: CommonCliOptions, fn: (engine: StarClawEngine) => void | Promise<void>) => async () => {
  try {
    await fn(createEngine(o, undefined, noLlm));
  } catch (e) {
    fatal(e);
  }
};
const scheduleCmd = program.command('schedule').description('manage unattended jobs (they only run while `starclaw daemon` is running)');
common(scheduleCmd.command('add <name> <schedule> <goal>'))
  .description('add a job: <schedule> is a 5-field cron expression or "@every 30m". YOU are creating it, so no approval prompt; it is audited.')
  .option('--heartbeat', 'heartbeat job: the agent messages you ONLY if something needs attention')
  .option('--notify <mode>', 'agent | summary | never (default: agent for heartbeats, summary otherwise)')
  .action((name: string, schedule: string, goal: string, o: CommonCliOptions & { heartbeat?: boolean; notify?: string }) =>
    withJobs(o, (engine) => {
      if (o.notify !== undefined && !['agent', 'summary', 'never'].includes(o.notify)) throw new Error('--notify must be agent, summary or never');
      const job = engine.jobs.add({ name, schedule, goal, kind: o.heartbeat ? 'heartbeat' : 'goal', notify: o.notify as any, createdBy: 'owner-cli' });
      engine.audit.append('scheduler.job.created', { jobId: job.id, name: job.name, kind: job.kind, schedule: job.schedule, createdBy: job.createdBy, createdTainted: false });
      console.log(`created ${job.id}; next run ${job.nextRunAt ? new Date(job.nextRunAt).toISOString() : 'never'}`);
    })(),
  );
common(scheduleCmd.command('list')).description('list jobs').action((o: CommonCliOptions) =>
  withJobs(o, (engine) => {
    const jobs = engine.jobs.list();
    if (!jobs.length) return console.log('no jobs');
    for (const j of jobs) console.log(`${j.id}  ${j.paused ? 'PAUSED' : 'active'}  ${j.kind}  "${j.schedule}"  ${j.name}  next=${j.nextRunAt ? new Date(j.nextRunAt).toISOString() : '-'}  last=${j.lastStatus ?? '-'}${j.pausedReason ? '  (' + j.pausedReason + ')' : ''}`);
  })(),
);
common(scheduleCmd.command('remove <id>')).description('delete a job').action((id: string, o: CommonCliOptions) =>
  withJobs(o, (engine) => {
    engine.audit.append('scheduler.job.removed', { jobId: id, by: 'owner-cli' });
    console.log(engine.jobs.remove(id) ? 'removed' : 'no such job');
  })(),
);
common(scheduleCmd.command('pause <id>')).description('pause a job').action((id: string, o: CommonCliOptions) =>
  withJobs(o, (engine) => {
    engine.audit.append('scheduler.job.paused', { jobId: id, reason: 'owner-cli' });
    console.log(engine.jobs.update(id, { paused: true, pausedReason: 'paused by owner' }) ? 'paused' : 'no such job');
  })(),
);
common(scheduleCmd.command('resume <id>')).description('resume a paused job (clears its failure count)').action((id: string, o: CommonCliOptions) =>
  withJobs(o, (engine) => {
    engine.audit.append('scheduler.job.resumed', { jobId: id, by: 'owner-cli' });
    console.log(engine.jobs.update(id, { paused: false, pausedReason: undefined, consecutiveFailures: 0 }) ? 'resumed' : 'no such job');
  })(),
);

// ---- signed skills registry (local files only; deliberately NOT an open store) ----------------------------------------

const skillsCmd = program.command('skills').description('signed, owner-approved skills registry (policy skillsRegistry; local .starclaw-skill files only, no network)');
const withEngine = (o: CommonCliOptions, approver: CliApprover | undefined, fn: (engine: StarClawEngine) => void | Promise<void>) => async () => {
  let engine: StarClawEngine | undefined;
  try {
    engine = createEngine(o, approver, noLlm);
    await fn(engine);
  } catch (e) {
    fatal(e);
  } finally {
    engine?.memory.close();
  }
};
const HEX64 = /^[0-9a-fA-F]{64}$/;

const keysCmd = skillsCmd.command('keys').description("the owner's keyring of pinned publisher keys: only skills signed by these can ever install or run");
common(keysCmd.command('add <publicKey>'))
  .description('pin a publisher: <publicKey> is the 64-hex Ed25519 public key, or a file containing it. Check the fingerprint with the publisher out of band.')
  .requiredOption('--label <text>', 'who this publisher is')
  .action((pub: string, o: CommonCliOptions & { label: string }) =>
    withEngine(o, undefined, (engine) => {
      const hex = HEX64.test(pub) ? pub : fs.readFileSync(pub, 'utf8').trim();
      const k = engine.registry.addKey(hex, o.label);
      console.log(`pinned publisher ${k.fingerprint} (${o.label})`);
    })(),
  );
common(keysCmd.command('list')).description('list pinned publishers').action((o: CommonCliOptions) =>
  withEngine(o, undefined, (engine) => {
    const ks = engine.registry.listKeys();
    if (!ks.length) return console.log('no publisher keys pinned');
    for (const k of ks) console.log(`${k.fingerprint}  ${k.label}`);
  })(),
);
common(keysCmd.command('remove <fingerprint>')).description('un-pin a publisher: every installed skill from it stops running immediately').action((fp: string, o: CommonCliOptions) =>
  withEngine(o, undefined, (engine) => {
    console.log(engine.registry.removeKey(fp) ? 'removed' : 'no such publisher');
  })(),
);

skillsCmd
  .command('keygen <keyFile>')
  .description('PUBLISHER: create a new Ed25519 signing key file (mode 0600, never overwrites). Prints the public key and fingerprint, never the private key.')
  .action((keyFile: string) => {
    try {
      const s = Ed25519Signer.createKeyFile(keyFile);
      console.log(`public key : ${s.publicKeyHex}\nfingerprint: ${fingerprint(s.publicKeyHex)}\nkey file    : ${keyFile} (keep it private; ${process.platform === 'win32' ? 'on Windows its protection is the directory ACL, not a mode' : 'mode 0600'})`);
    } catch (e) {
      fatal(e);
    }
  });
skillsCmd
  .command('sign <dir>')
  .description('PUBLISHER: bundle and sign a skill. <dir> holds skill.json {id,version,description,entry,expiresAt?,capabilities} plus the flat code files.')
  .requiredOption('--key <keyFile>', 'publisher key file (refused if group/other readable on POSIX)')
  .requiredOption('--out <file>', 'output .starclaw-skill file (never overwritten)')
  .action((dir: string, o: { key: string; out: string }) => {
    try {
      const signer = Ed25519Signer.loadKeyFile(o.key);
      const draft = JSON.parse(fs.readFileSync(path.join(dir, 'skill.json'), 'utf8'));
      const members: Record<string, string> = {};
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (ent.name === 'skill.json') continue;
        if (!ent.isFile()) throw new Error(`${ent.name}: only regular files are bundled (no directories or links)`);
        const st = fs.statSync(path.join(dir, ent.name));
        if (st.size > 262_144) throw new Error(`${ent.name} is larger than 256 KB`);
        members[ent.name] = fs.readFileSync(path.join(dir, ent.name), 'utf8');
      }
      fs.writeFileSync(o.out, buildBundle(draft, members, signer), { flag: 'wx' });
      console.log(`signed ${draft.id}@${draft.version} as publisher ${fingerprint(signer.publicKeyHex)} -> ${o.out}`);
    } catch (e) {
      fatal(e);
    }
  });
common(skillsCmd.command('verify <file>'))
  .description('verify a bundle against YOUR keyring (pinned publisher, signature, hashes, expiry, revocation); installs nothing; exit 1 if it fails')
  .action((file: string, o: CommonCliOptions) =>
    withEngine(o, undefined, (engine) => {
      try {
        const v = engine.registry.verifyFile(file);
        const m = v.manifest;
        console.log(`OK: ${m.id}@${m.version} signed by pinned publisher ${m.publisher} ("${v.publisher.label}"); bundle sha256 ${v.bundleSha256}`);
        for (const l of describeCaps(m.capabilities)) console.log('  ' + l);
      } catch (e: any) {
        console.log(`REFUSED: ${e.message}`);
        process.exitCode = 1;
      }
    })(),
  );
common(skillsCmd.command('install <file>'))
  .description('install a .starclaw-skill file after YOU approve it (shown: publisher fingerprint, version, declared capabilities, diff vs any installed version). No approver = denied.')
  .option('--allow-rollback', 'permit a lower/same version replacing the installed one (still needs a fresh approval)')
  .option('--allow-publisher-change', 'permit a different publisher replacing the installed skill (still needs a fresh approval)')
  .action(async (file: string, o: CommonCliOptions & { allowRollback?: boolean; allowPublisherChange?: boolean }) => {
    let rl: readline.Interface | undefined;
    let approver: CliApprover | undefined;
    if (process.stdin.isTTY) {
      rl = readline.createInterface({ input: process.stdin, output: process.stderr });
      approver = new CliApprover(
        (prompt, signal) => new Promise((res, rej) => { signal.addEventListener('abort', () => rej(new Error('timeout'))); rl!.question(prompt, { signal }, res); }),
        (s) => console.error(s),
      );
    } else console.error('starclaw: stdin is not a terminal, so no one can approve: the install will be denied.');
    await withEngine(o, approver, async (engine) => {
      try {
        const r = await engine.installRegistrySkill(file, { allowRollback: o.allowRollback, allowPublisherChange: o.allowPublisherChange });
        console.log(r.alreadyInstalled ? `${r.id}@${r.version} is already installed (identical bundle)` : `installed ${r.id}@${r.version} (publisher ${r.publisher})`);
      } catch (e: any) {
        console.error(`REFUSED: ${e.message}`);
        process.exitCode = 1;
      }
    })();
    rl?.close();
  });
common(skillsCmd.command('list')).description('list installed registry skills and whether each would run right now').action((o: CommonCliOptions) =>
  withEngine(o, undefined, (engine) => {
    const l = engine.registry.list();
    if (!l.length) return console.log('no registry skills installed');
    for (const s of l) console.log(`${s.id}@${s.version}  publisher ${s.publisher} (${s.label ?? 'NOT PINNED'})  ${s.status}  installed ${s.installedAt}`);
  })(),
);
common(skillsCmd.command('revoke [id]'))
  .description('revoke a skill by id (all versions unless --version), or import a signed revocation list from a pinned publisher with --list')
  .option('--version <v>', 'only this version')
  .option('--reason <text>', 'why')
  .option('--list <file>', 'import a signed revocation list instead of naming an id')
  .action((id: string | undefined, o: CommonCliOptions & { version?: string; reason?: string; list?: string }) =>
    withEngine(o, undefined, (engine) => {
      if (o.list) return void console.log(`imported ${engine.registry.importRevocationList(o.list)} revocation(s)`);
      if (!id) throw new Error('give a skill id, or --list <file>');
      engine.registry.revoke(id, { version: o.version, reason: o.reason });
      console.log(`revoked ${id}${o.version ? '@' + o.version : ' (all versions)'}; it refuses to run from now on`);
    })(),
  );


// ---- Slack / Discord (webhook channels; configured in the policy, secrets only from the environment) ----------------

const policyOpt = (c: Command) => c.option('--policy <file>', 'policy JSON file');
const slackCmd = program.command('slack').description('Slack channel (goals + approvals + owner notifications over a signed webhook)');
policyOpt(slackCmd.command('status'))
  .description('check the Slack policy block and environment (prints variable names and set/NOT set, never values); exit 1 if enabled but misconfigured')
  .action((o: { policy?: string }) => {
    try {
      const policy = loadPolicy(o.policy);
      const s = slackStatus(policy, process.env);
      console.log(s.line);
      for (const w of s.warnings) console.log('  WARNING: ' + w);
      console.log(listenerStatus(policy).line);
      console.log('Slack app needs: bot scopes chat:write + im:history; event subscription message.im -> <your tunnel>/slack/events; interactivity -> <your tunnel>/slack/interactions.');
      process.exit(s.broken ? 1 : 0);
    } catch (e) {
      fatal(e);
    }
  });
const discordCmd = program.command('discord').description('Discord channel (/starclaw slash command + approval buttons over a signed webhook)');
policyOpt(discordCmd.command('status'))
  .description('check the Discord policy block and environment (names and set/NOT set only); exit 1 if enabled but misconfigured')
  .action((o: { policy?: string }) => {
    try {
      const policy = loadPolicy(o.policy);
      const s = discordStatus(policy, process.env);
      console.log(s.line);
      for (const w of s.warnings) console.log('  WARNING: ' + w);
      console.log(listenerStatus(policy).line);
      console.log('Discord app needs: Interactions Endpoint URL -> <your tunnel>/discord/interactions; then run: starclaw discord register');
      process.exit(s.broken ? 1 : 0);
    } catch (e) {
      fatal(e);
    }
  });
policyOpt(discordCmd.command('register'))
  .description('register the /starclaw slash command with Discord (contacts discord.com using the bot token from the environment)')
  .option('--guild <id>', 'register in one server only (appears instantly) instead of globally')
  .action(async (o: { policy?: string; guild?: string }) => {
    try {
      const policy = loadPolicy(o.policy);
      if (!policy.discord.enabled) throw new Error('discord.enabled is false in the policy');
      const cfg = resolveDiscordConfig(policy, process.env);
      const n = await registerDiscordCommand(new FetchDiscordApi(cfg.botToken), cfg.applicationId, o.guild);
      console.log(`registered ${n} command(s) ${o.guild ? 'in guild ' + o.guild : 'globally'}`);
    } catch (e) {
      fatal(e);
    }
  });

common(program.command('app'))
  .description('local console in your browser: runs in the app home (default %LOCALAPPDATA%\\StarClaw, ~/.starclaw-app elsewhere, or STARCLAW_HOME), listens on 127.0.0.1 only, and opens the console already holding its key')
  .option('--home <dir>', 'app home directory (its .env, starclaw.policy.json, .starclaw/ and workspace are used)')
  .option('--port <n>', 'port on 127.0.0.1 (default: a free one)', '0')
  .option('--no-open', 'do not open a browser; print the address instead')
  .option('--setup', 'open the guided model setup page even if a model is already configured')
  .action(async (o: CommonCliOptions & { home?: string; port: string; open: boolean; setup?: boolean }) => {
    try {
      const port = Number(o.port);
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('--port must be 0..65535');
      // Paths given on the command line are relative to where the user typed them, not to the app home.
      for (const k of ['policy', 'stateDir', 'workspace'] as const) if (o[k]) o[k] = path.resolve(o[k]!);
      const home = o.home ? path.resolve(o.home) : defaultAppHome();
      const { envFile, apiKey, created } = prepareAppHome(home);
      process.chdir(home);
      dotenv.config({ path: envFile, quiet: true } as any);
      const boot = async () => {
        const approver = new HttpApprover();
        const engine = createEngine(o, approver); // re-reads starclaw.policy.json in the home (the cwd)
        await engine.boot();
        return { engine, approver };
      };
      let started: Awaited<ReturnType<typeof boot>> | undefined;
      if (!o.setup) {
        try {
          started = await boot();
        } catch (e: any) {
          // Only a missing/unusable model sends the user to setup; anything else (e.g. a bad policy) stops here.
          if (!isModelConfigError(e)) throw e;
          console.log(`No usable AI model yet (${e.message}). Opening guided setup.`);
        }
      }
      const a = await startApp({ apiKey, port, open: o.open ? undefined : false, ...(started ?? { setup: { home, boot } }) });
      console.log(`StarClaw ${VERSION} ${a.mode() === 'setup' ? 'setup' : 'console'}: http://127.0.0.1:${a.port}/  (home ${home}${created ? '; new console key written to .env' : ''}; keys in ${envFile})`);
      if (!o.open) console.log(`open with the key: ${a.url}`);
      console.log('Ctrl+C stops it.');
    } catch (e) {
      fatal(e);
    }
  });

common(program.command('daemon'))
  .description('long-running process: Telegram gateway (goals + async approvals), Slack/Discord webhook channels when enabled in the policy, and the scheduler. Telegram needs TELEGRAM_BOT_TOKEN and TELEGRAM_OWNER_ID.')
  .option('--no-telegram', 'run without Telegram: jobs run but every approval is denied and nothing can message you')
  .action(async (o: CommonCliOptions & { telegram?: boolean }) => {
    try {
      const d = await runDaemon({ ...o, noTelegram: o.telegram === false });
      const stop = () => { d.stop(); process.exit(0); };
      process.on('SIGINT', stop);
      process.on('SIGTERM', stop);
    } catch (e) {
      fatal(e);
    }
  });

program.parseAsync(process.argv).catch(fatal);
