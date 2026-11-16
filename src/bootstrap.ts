import * as dotenv from 'dotenv';
import { StarClawEngine, EngineOptions } from './engine';
import { loadPolicy, Policy } from './governance/policy';
import { GroqLLM } from './llm/GroqLLM';
import type { Approver } from './governance/types';

export interface CommonCliOptions {
  policy?: string;
  stateDir?: string;
  workspace?: string;
  learnSkills?: boolean;
  sandbox?: string;
  requireContainer?: boolean;
}

/** Apply --sandbox / --require-container on top of the loaded policy. */
export function applySandboxFlags(policy: Policy, o: CommonCliOptions): Policy {
  const sandbox = { ...policy.sandbox };
  if (o.sandbox !== undefined) {
    if (!['auto', 'container', 'process'].includes(o.sandbox)) throw new Error('--sandbox must be auto, container or process');
    sandbox.mode = o.sandbox as Policy['sandbox']['mode'];
  }
  if (o.requireContainer) sandbox.requireContainer = true;
  return { ...policy, sandbox };
}

/** Build an engine from CLI options + environment. Throws PolicyError on an invalid policy (fail closed). */
export function createEngine(opts: CommonCliOptions, approver: Approver | undefined, extra: Partial<EngineOptions> = {}): StarClawEngine {
  dotenv.config({ quiet: true } as any);
  const policy = applySandboxFlags(loadPolicy(opts.policy), opts);
  return new StarClawEngine({
    llm: extra.llm ?? new GroqLLM(),
    policy,
    stateDir: opts.stateDir ?? process.env.STARCLAW_STATE_DIR,
    workspaceDir: opts.workspace,
    approver,
    learnSkills: opts.learnSkills,
    ...extra,
  });
}
