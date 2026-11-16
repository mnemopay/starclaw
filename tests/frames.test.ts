import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { FrameParser } from '../src/sandbox/frames';

const NONCE = 'a'.repeat(32);
const frame = (obj: unknown, nonce = NONCE) => `@sc:${nonce}:${JSON.stringify(obj)}\n`;

function parse(chunks: Array<string | Buffer>, opts: { nonce?: string | null; max?: number } = {}) {
  const frames: any[] = [];
  const text: string[] = [];
  const fatal: string[] = [];
  const p = new FrameParser({
    nonce: opts.nonce === undefined ? NONCE : opts.nonce,
    maxFrameBytes: opts.max ?? 1000,
    onFrame: (f) => frames.push(f),
    onText: (t) => text.push(t),
    onFatal: (r) => fatal.push(r),
  });
  for (const c of chunks) p.push(Buffer.from(c));
  p.end();
  return { frames, text: text.join(''), fatal, forged: p.forged };
}

describe('frame parser (hostile input)', () => {
  test('CONTROL: a genuine frame, even split across chunks and mixed with output, is parsed', () => {
    const f = frame({ type: 'call', id: 1, name: 'readFile', args: {} });
    const r = parse(['hello\n', f.slice(0, 10), f.slice(10), 'bye\n']);
    assert.equal(r.frames.length, 1);
    assert.equal(r.frames[0].name, 'readFile');
    assert.equal(r.text, 'hello\nbye\n');
    assert.deepEqual(r.fatal, []);
  });

  test('forged frames (wrong nonce, no nonce, empty nonce, guessed nonce prefix) are plain output, never frames', () => {
    const fakes = [frame({ type: 'done', ok: true, value: '"pwned"' }, 'b'.repeat(32)), '@sc::{"type":"done"}\n', '@sc:{"type":"call","id":1,"name":"spend"}\n', `@sc:${NONCE.slice(0, 31)}:{"type":"done"}\n`, `@sc:${NONCE}x:{"type":"done"}\n`];
    const r = parse(fakes);
    assert.equal(r.frames.length, 0);
    assert.equal(r.forged, fakes.length);
    assert.equal(r.text, fakes.join(''));
  });

  test('CONTROL: with nonce checking switched off the same forgeries are accepted (so the nonce is what protects)', () => {
    const r = parse([frame({ type: 'done', ok: true, value: '"pwned"' }, 'whatever')], { nonce: null });
    assert.equal(r.frames.length, 1);
  });

  test('a frame prefix not at the start of a line is output; a partial frame at end of stream is output', () => {
    const r = parse([`junk ${frame({ type: 'done' }).trimEnd()}\n`, frame({ type: 'call', id: 2, name: 'x' }).trimEnd()]); // second has no newline
    assert.equal(r.frames.length, 0);
    assert.match(r.text, /junk @sc:/);
    assert.equal(r.forged, 1);
  });

  test('invalid JSON carrying the correct nonce is fatal (only the runner can produce it)', () => {
    const r = parse([`@sc:${NONCE}:{not json\n`, frame({ type: 'done' })]);
    assert.equal(r.fatal.length, 1);
    assert.equal(r.frames.length, 0, 'nothing after the violation is processed');
    for (const bad of ['[]', '"str"', '42', 'null']) assert.equal(parse([`@sc:${NONCE}:${bad}\n`]).fatal.length, 1, bad);
  });

  test('giant frames and giant unterminated lines are fatal, not buffered without bound', () => {
    assert.equal(parse([frame({ type: 'call', id: 1, name: 'writeFile', args: { content: 'x'.repeat(5000) } })]).fatal.length, 1);
    const r = parse(['x'.repeat(600), 'y'.repeat(600)]); // never a newline
    assert.equal(r.fatal.length, 1);
    assert.match(r.fatal[0], /exceeds/);
  });

  test('multi-byte characters split across chunk boundaries survive', () => {
    const f = Buffer.from(frame({ type: 'call', id: 3, name: 'x', args: { s: 'héllo €😀' } }));
    const mid = f.indexOf(0xc3) + 1; // split inside "é"
    const r = parse([f.subarray(0, mid), f.subarray(mid)], { max: 10_000 });
    assert.equal(r.frames[0].args.s, 'héllo €😀');
  });

  test('CRLF and blank lines in output are harmless', () => {
    const r = parse(['a\r\n\n\n', frame({ type: 'done' })]);
    assert.equal(r.frames.length, 1);
    assert.equal(r.text, 'a\r\n\n\n');
  });
});
