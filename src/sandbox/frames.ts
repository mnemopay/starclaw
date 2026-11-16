import { StringDecoder } from 'node:string_decoder';

/**
 * Stdio frame transport used across the container boundary (there is no IPC fd to a container).
 *
 * Frames are single lines on the child's stdout:  `@sc:<nonce>:<json>\n`.
 *
 * FORGERY ANALYSIS. Generated code shares stdout with the runner, so it can print any text, including
 * something that looks like a frame. Two independent defences:
 *  1. The nonce is 128 random bits generated per run by the parent and delivered over stdin to the runner,
 *     which keeps it in a closure generated code cannot reach. A line without the exact nonce is plain output.
 *  2. Even a forged frame would be harmless: every `call` frame is validated and routed through the broker and
 *     Governor exactly as if the code had called `tools.*` itself (generated code can already do that), and a
 *     forged `done` can only change the untrusted result of that same run.
 * The parser is also hostile-input safe: bounded line length, invalid JSON after a valid nonce is fatal (only the
 * runner can produce it), frames after `done` are ignored.
 */
export const FRAME_PREFIX = '@sc:';

export interface FrameParserOptions {
  /** null = TEST-ONLY control that accepts any nonce (proves the nonce is what stops forged frames). */
  nonce: string | null;
  maxFrameBytes: number;
  onFrame(frame: Record<string, unknown>): void;
  onText(text: string): void;
  onFatal(reason: string): void;
}

export class FrameParser {
  private buf = '';
  private readonly dec = new StringDecoder('utf8');
  private readonly marker: string | null;
  private fatal = false;
  forged = 0;

  constructor(private readonly o: FrameParserOptions) {
    this.marker = o.nonce === null ? null : `${FRAME_PREFIX}${o.nonce}:`;
  }

  push(chunk: Buffer): void {
    if (this.fatal) return;
    this.buf += this.dec.write(chunk);
    let nl: number;
    while ((nl = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + 1);
      this.line(line);
      if (this.fatal) return;
    }
    if (this.buf.length > this.o.maxFrameBytes) {
      this.fatal = true;
      this.o.onFatal(`output line exceeds ${this.o.maxFrameBytes} bytes without a newline`);
    }
  }

  /** Stream ended: a trailing partial line (no newline) is plain text, never a frame. */
  end(): void {
    if (this.fatal) return;
    this.buf += this.dec.end();
    if (this.buf.length) {
      if (this.buf.startsWith(FRAME_PREFIX)) this.forged++;
      this.o.onText(this.buf);
    }
    this.buf = '';
  }

  private line(line: string) {
    if (line.length > this.o.maxFrameBytes) {
      this.fatal = true;
      this.o.onFatal(`frame/line of ${line.length} bytes exceeds ${this.o.maxFrameBytes}`);
      return;
    }
    const anyNonce = this.marker === null ? /^@sc:[^:]*:/.exec(line) : null;
    const markerLen = this.marker !== null ? (line.startsWith(this.marker) ? this.marker.length : -1) : anyNonce ? anyNonce[0].length : -1;
    if (markerLen >= 0) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line.slice(markerLen));
      } catch {
        this.fatal = true;
        this.o.onFatal('malformed frame carrying the correct nonce');
        return;
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        this.fatal = true;
        this.o.onFatal('frame is not a JSON object');
        return;
      }
      this.o.onFrame(parsed as Record<string, unknown>);
      return;
    }
    if (line.startsWith(FRAME_PREFIX)) this.forged++; // looks like a frame, wrong nonce: just output
    this.o.onText(line + '\n');
  }
}
