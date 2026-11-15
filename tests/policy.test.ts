import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { defaultPolicy, evaluatePolicy, loadPolicy, parsePolicy, PolicyError } from '../src/governance/policy';
import { rm, tmpDir, policyWith } from './helpers';

describe('policy', () => {
  test('defaults are conservative: ask for everything except in-workspace reads; no spend allowance', () => {
    const p = defaultPolicy();
    for (const c of ['exec', 'fs.write', 'net.egress', 'spend', 'skill.save', 'memory.write'] as const) {
      assert.equal(evaluatePolicy(p, { class: c, target: 'x', summary: '', cents: 1 }).verdict, 'ask', c);
    }
    assert.equal(evaluatePolicy(p, { class: 'fs.read', target: '/w/a', summary: '', inWorkspace: true }).verdict, 'allow');
    assert.equal(evaluatePolicy(p, { class: 'fs.read', target: '/etc/x', summary: '', inWorkspace: false }).verdict, 'ask');
    assert.equal(p.spend.maxPerActionCents, 0);
    assert.equal(p.spend.maxTotalCents, 0);
    assert.equal(p.net.allowPrivateAddresses, false);
  });

  test('invalid policies fail closed with PolicyError', () => {
    const bad: Array<[string, string]> = [
      ['not json', '{nope'],
      ['unknown top-level key', JSON.stringify({ version: 1, yolo: true })],
      ['wrong version', JSON.stringify({ version: 2 })],
      ['bad verdict', JSON.stringify({ version: 1, defaults: { exec: 'maybe' } })],
      ['unknown action class in defaults', JSON.stringify({ version: 1, defaults: { teleport: 'allow' } })],
      ['unknown class in rule', JSON.stringify({ version: 1, rules: [{ class: 'teleport', verdict: 'allow' }] })],
      ['fractional cents', JSON.stringify({ version: 1, spend: { maxPerActionCents: 1.5 } })],
      ['negative cents', JSON.stringify({ version: 1, spend: { maxTotalCents: -1 } })],
      ['unknown rule key', JSON.stringify({ version: 1, rules: [{ class: 'exec', verdict: 'allow', everything: true }] })],
      ['timeout too small', JSON.stringify({ version: 1, approvalTimeoutSeconds: 0 })],
      ['array', '[]'],
    ];
    for (const [name, text] of bad) assert.throws(() => parsePolicy(text), PolicyError, name);
  });

  test('a missing explicit policy file is an error, never a silent fallback', () => {
    assert.throws(() => loadPolicy(path.join(tmpDir(), 'nope.json')), PolicyError);
  });

  test('a corrupt policy file on disk is an error', () => {
    const d = tmpDir();
    try {
      const f = path.join(d, 'p.json');
      fs.writeFileSync(f, '{"version":1,"defaults":{"exec":"allow"');
      assert.throws(() => loadPolicy(f), PolicyError);
    } finally {
      rm(d);
    }
  });

  test('deny rules override allow rules regardless of order', () => {
    const p = policyWith({
      rules: [
        { class: 'net.egress', target: '*.example.com', verdict: 'allow' },
        { class: 'net.egress', target: 'evil.example.com', verdict: 'deny' },
      ],
    });
    const ev = (host: string) => evaluatePolicy(p, { class: 'net.egress', target: host, host, summary: '' }).verdict;
    assert.equal(ev('docs.example.com'), 'allow');
    assert.equal(ev('evil.example.com'), 'deny');
    assert.equal(ev('other.org'), 'ask');
  });

  test('spend rules honour maxCents', () => {
    const p = policyWith({ rules: [{ class: 'spend', maxCents: 100, verdict: 'allow' }] });
    assert.equal(evaluatePolicy(p, { class: 'spend', target: 'x', summary: '', cents: 100 }).verdict, 'allow');
    assert.equal(evaluatePolicy(p, { class: 'spend', target: 'x', summary: '', cents: 101 }).verdict, 'ask');
  });
});
