/**
 * Minimal 5-field cron (minute hour day-of-month month day-of-week) with lists, ranges and steps, evaluated in an
 * IANA timezone. Also supports "@every <N>s|m|h" intervals. No names (JAN, MON) and no L/W/# extensions: unsupported
 * syntax is rejected, never guessed.
 */
export interface IntervalSpec {
  kind: 'interval';
  seconds: number;
}
export interface CronSpec {
  kind: 'cron';
  minutes: Set<number>;
  hours: Set<number>;
  dom: Set<number>;
  months: Set<number>;
  dow: Set<number>;
  domStar: boolean;
  dowStar: boolean;
  /** Smallest gap, in minutes, that this expression can produce (computed by walking one year). */
  minGapMinutes: number;
}
export type Schedule = IntervalSpec | CronSpec;

function field(src: string, min: number, max: number): { set: Set<number>; star: boolean } {
  const set = new Set<number>();
  let star = false;
  for (const part of src.split(',')) {
    if (part === '') throw new Error(`empty list item in "${src}"`);
    const pieces = part.split('/');
    if (pieces.length > 2) throw new Error(`bad step in "${part}"`);
    const [rangeRaw, stepRaw] = pieces;
    let step = 1;
    if (stepRaw !== undefined) {
      if (!/^\d+$/.test(stepRaw) || Number(stepRaw) < 1) throw new Error(`bad step "${stepRaw}"`);
      step = Number(stepRaw);
    }
    let lo: number;
    let hi: number;
    if (rangeRaw === '*') {
      lo = min;
      hi = max;
      if (stepRaw === undefined) star = true;
    } else if (/^\d+$/.test(rangeRaw)) {
      lo = Number(rangeRaw);
      hi = stepRaw !== undefined ? max : lo;
    } else if (/^\d+-\d+$/.test(rangeRaw)) {
      [lo, hi] = rangeRaw.split('-').map(Number);
    } else throw new Error(`unsupported cron syntax "${part}"`);
    if (lo < min || hi > max || lo > hi) throw new Error(`value out of range in "${part}" (allowed ${min}-${max})`);
    for (let v = lo; v <= hi; v += step) set.add(v);
  }
  return { set, star };
}

const fmtCache = new Map<string, Intl.DateTimeFormat>();
const tzParts = (d: Date, tz: string) => {
  let f = fmtCache.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', weekday: 'short' });
    fmtCache.set(tz, f);
  }
  const o: Record<string, string> = {};
  for (const p of f.formatToParts(d)) o[p.type] = p.value;
  const wd = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(o.weekday);
  return { minute: Number(o.minute), hour: Number(o.hour) % 24, dom: Number(o.day), month: Number(o.month), dow: wd };
};

function dayOk(c: CronSpec, dom: number, dow: number): boolean {
  const domOk = c.dom.has(dom);
  const dowOk = c.dow.has(dow);
  // Standard cron: if both day fields are restricted, either may match.
  if (!c.domStar && !c.dowStar) return domOk || dowOk;
  return domOk && dowOk;
}

export function parseSchedule(expr: string, tz = 'UTC'): Schedule {
  const e = expr.trim();
  const ev = /^@every\s+(\d+)\s*(s|m|h)$/i.exec(e);
  if (ev) {
    const unit = ev[2].toLowerCase();
    const n = Number(ev[1]) * (unit === 's' ? 1 : unit === 'm' ? 60 : 3600);
    if (!Number.isSafeInteger(n) || n < 1) throw new Error('bad interval');
    return { kind: 'interval', seconds: n };
  }
  const f = e.split(/\s+/);
  if (f.length !== 5) throw new Error('expected 5 cron fields (minute hour day-of-month month day-of-week) or "@every <N>s|m|h"');
  const m = field(f[0], 0, 59);
  const h = field(f[1], 0, 23);
  const dom = field(f[2], 1, 31);
  const mon = field(f[3], 1, 12);
  const dowRaw = field(f[4], 0, 7);
  const dow = new Set([...dowRaw.set].map((v) => v % 7));
  const spec: CronSpec = { kind: 'cron', minutes: m.set, hours: h.set, dom: dom.set, months: mon.set, dow, domStar: dom.star, dowStar: dowRaw.star, minGapMinutes: 0 };
  // Shortest gap and "does it ever fire", computed on a naive calendar (a leap year, no DST): at most an hour off on DST days.
  const times = [...h.set].flatMap((hh) => [...m.set].map((mm) => hh * 60 + mm)).sort((x, y) => x - y);
  let gap = Infinity;
  for (let i = 1; i < times.length; i++) gap = Math.min(gap, times[i] - times[i - 1]);
  let prevDay: number | undefined;
  let fires = false;
  for (let d = 0; d < 366; d++) {
    const dt = new Date(Date.UTC(2028, 0, 1 + d));
    if (!spec.months.has(dt.getUTCMonth() + 1) || !dayOk(spec, dt.getUTCDate(), dt.getUTCDay())) continue;
    fires = true;
    if (prevDay !== undefined) gap = Math.min(gap, (d - prevDay) * 1440 - times[times.length - 1] + times[0]);
    prevDay = d;
  }
  if (!fires) throw new Error('this cron expression never fires');
  spec.minGapMinutes = Number.isFinite(gap) ? gap : 525_600;
  return spec;
}

/** The shortest gap this schedule can produce, in seconds. */
export function minGapSeconds(s: Schedule): number {
  return s.kind === 'interval' ? s.seconds : s.minGapMinutes * 60;
}

/** Next fire time strictly after the given time (epoch ms), or undefined if none within 400 days. Skips whole days/hours that cannot match. */
export function nextFire(s: Schedule, after: number, tz = 'UTC'): number | undefined {
  if (s.kind === 'interval') return after + s.seconds * 1000;
  let t = Math.floor(after / 60_000) * 60_000 + 60_000;
  const limit = after + 400 * 86_400_000;
  while (t <= limit) {
    const p = tzParts(new Date(t), tz);
    if (!s.months.has(p.month) || !dayOk(s, p.dom, p.dow)) {
      t += (1440 - (p.hour * 60 + p.minute)) * 60_000; // to the next local midnight
      continue;
    }
    if (!s.hours.has(p.hour)) {
      t += (60 - p.minute) * 60_000; // to the next local hour
      continue;
    }
    if (!s.minutes.has(p.minute)) {
      t += 60_000;
      continue;
    }
    return t;
  }
  return undefined;
}
