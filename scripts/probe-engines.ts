/**
 * Regenerate `data/engine-probe.json` from real browsers.
 *
 * The analyzer's model of which names are protected is derived from this data,
 * so this script is the mechanism that keeps the tool honest as browsers change.
 * It walks each engine's `window` and `document` property chains and records
 * every reachable property name.
 *
 * Requirements: Chrome (or Chromium), and the Playwright Firefox and WebKit
 * builds. See `scripts/setup-browsers.sh`. Run with `npm run probe`.
 */

import { writeFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { browserPaths } from '../e2e/browser.ts';
import type { EngineName } from '../e2e/browser.ts';

const require = createRequire(import.meta.url);

/** Shape stored per engine in data/engine-probe.json. */
interface ChainDump {
  userAgent: string;
  windowChain: string[];
  documentChain: string[];
  documentOwn: string[];
}

/** Raw shape returned from the page. */
interface RawDump {
  ua: string;
  win: string[];
  doc: string[];
  docOwn: string[];
}

const DUMP = (): RawDump => {
  const all = (o: object): string[] => {
    const seen = new Set<string>();
    let cur: object | null = o;
    let depth = 0;
    while (cur && depth < 12) {
      for (const k of Object.getOwnPropertyNames(cur)) seen.add(k);
      cur = Object.getPrototypeOf(cur);
      depth++;
    }
    return [...seen];
  };
  return {
    ua: navigator.userAgent,
    win: all(window),
    doc: all(document),
    docOwn: Object.getOwnPropertyNames(document),
  };
};

function normalize(raw: RawDump): ChainDump {
  return {
    userAgent: raw.ua,
    windowChain: [...new Set(raw.win)].sort(),
    documentChain: [...new Set(raw.doc)].sort(),
    documentOwn: [...new Set(raw.docOwn)].sort(),
  };
}

async function probeChrome(exe: string): Promise<RawDump> {
  const puppeteer = require('puppeteer-core') as typeof import('puppeteer-core');
  const browser = await puppeteer.launch({ executablePath: exe, headless: true, args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage();
    await page.goto('data:text/html,<body>');
    return (await page.evaluate(DUMP as unknown as () => RawDump)) as RawDump;
  } finally {
    await browser.close();
  }
}

async function probePlaywright(engine: 'firefox' | 'webkit', exe: string): Promise<RawDump> {
  const pw = require('playwright-core') as typeof import('playwright-core');
  const browser = await pw[engine].launch({ executablePath: exe, headless: true });
  try {
    const page = await browser.newPage();
    await page.goto('data:text/html,<body>');
    return (await page.evaluate(DUMP as unknown as () => RawDump)) as RawDump;
  } finally {
    await browser.close();
  }
}

/**
 * Probe at an http origin too. Some engines expose different members on opaque
 * origins (data:), so we prefer http.
 */
async function withHttp<T>(fn: (url: string) => Promise<T>): Promise<T> {
  const srv = http.createServer((_q, s) => {
    s.writeHead(200, { 'content-type': 'text/html' });
    s.end('<!doctype html><body></body>');
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  try {
    return await fn(`http://127.0.0.1:${(srv.address() as AddressInfo).port}/`);
  } finally {
    await new Promise<void>((r) => srv.close(() => r()));
  }
}

export async function main(): Promise<number> {
  const paths = browserPaths();
  const engines: Array<[EngineName, () => Promise<RawDump>]> = [];
  if (paths.chrome) engines.push(['chrome', () => probeChrome(paths.chrome!)]);
  if (paths.firefox) engines.push(['firefox', () => probePlaywright('firefox', paths.firefox!)]);
  if (paths.webkit) engines.push(['webkit', () => probePlaywright('webkit', paths.webkit!)]);

  if (engines.length === 0) {
    console.error('No browsers available. Run scripts/setup-browsers.sh first.');
    return 1;
  }

  const out: Record<string, ChainDump> = {};
  for (const [name, fn] of engines) {
    const dump = normalize(await fn());
    out[name] = dump;
    console.log(
      `${name}: window chain ${dump.windowChain.length}, document chain ${dump.documentChain.length} (${dump.userAgent.slice(0, 50)}…)`,
    );
  }

  const payload = {
    provenance: {
      measuredAt: new Date().toISOString().slice(0, 10),
      method:
        'Live headless-browser probe: walk each global/prototype property chain and enumerate own+inherited property names.',
      userAgents: Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.userAgent])),
    },
    engines: out,
  };

  const here = dirname(fileURLToPath(import.meta.url));
  const dataPath = resolve(here, '..', 'data', 'engine-probe.json');
  if (!existsSync(dirname(dataPath))) {
    console.error(`data directory missing at ${dirname(dataPath)}`);
    return 1;
  }
  writeFileSync(dataPath, JSON.stringify(payload, null, 1) + '\n');
  console.log(`wrote ${dataPath}`);
  return 0;
}

const invokedDirectly = process.argv[1] && import.meta.url === `file://${resolve(process.argv[1])}`;
if (invokedDirectly) {
  main().then((code) => process.exit(code));
}
