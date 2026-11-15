import * as dotenv from 'dotenv';
import { StarClawEngine, EngineOptions } from './engine';
import { loadPolicy } from './governance/policy';
import { GroqLLM } from './llm/GroqLLM';
import type { Approver } from './governance/types';

export interface CommonCliOptions {
  policy?: string;
  stateDir?: string;
  workspace?: string;
  learnSkills?: boolean;
}

/** Build an engine from CLI options + environment. Throws PolicyError on an invalid policy (fail closed). */
export function createEngine(opts: CommonCliOptions, approver: Approver | undefined, extra: Partial<EngineOptions> = {}): StarClawEngine {
  dotenv.config({ quiet: true } as any);
  const policy = loadPolicy(opts.policy);
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
