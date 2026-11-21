/**
 * Real-browser harness.
 *
 * Serves a page over HTTP (named access behaves differently on file:// and on
 * opaque origins), injects the attacker payload into the declared region,
 * waits for load, and evaluates the oracle expression. Also serves the attacker
 * script so a successful takeover can be observed end-to-end.
 *
 * The harness is engine-agnostic: Chrome is driven with puppeteer-core, Firefox
 * and WebKit with playwright-core, because that is what can launch the engines
 * available in this environment.
 */

import http from 'node:http';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export type EngineName = 'chrome' | 'firefox' | 'webkit';

export interface PageMount {
  /** Full HTML served at `/`. */
  html: string;
  /** Script bodies served at their ids, e.g. `/app.js`. */
  scripts: Array<{ path: string; body: string; kind?: 'script' | 'module' }>;
  /** The attacker script served at `/attacker.js`. */
  attackerBody: string;
}

export interface ProbeOutcome {
  engine: EngineName;
  /** True when the oracle expression evaluated to true. */
  fired: boolean;
  /** Any page error seen while loading (often expected for crash impacts). */
  pageErrors: string[];
  /** The value the oracle returned, for debugging. */
  raw: unknown;
  /** Console errors, useful when a "crash" signal depends on a throw. */
  consoleErrors: string[];
}

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

/** Locate the browser engines, honoring env overrides. */
export function browserPaths(): { chrome?: string; firefox?: string; webkit?: string } {
  const root = resolve(here, '..');
  const browsers = process.env.CLOBBER_BROWSERS_DIR ?? resolve(root, '.browsers');
  const chromeCandidates = [
    process.env.CLOBBER_CHROME_PATH,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome',
  ].filter((p): p is string => Boolean(p));
  const firefoxCandidates = [
    process.env.CLOBBER_FIREFOX_PATH,
    resolve(browsers, 'firefox/Nightly.app/Contents/MacOS/firefox'),
  ].filter((p): p is string => Boolean(p));
  const webkitCandidates = [process.env.CLOBBER_WEBKIT_PATH, resolve(browsers, 'pw_run.sh')].filter(
    (p): p is string => Boolean(p),
  );
  const first = (xs: string[]) => xs.find((p) => existsSync(p));
  return {
    chrome: first(chromeCandidates),
    firefox: first(firefoxCandidates),
    webkit: first(webkitCandidates),
  };
}

export function availableEngines(): EngineName[] {
  const p = browserPaths();
  const out: EngineName[] = [];
  if (p.chrome) out.push('chrome');
  if (p.firefox) out.push('firefox');
  if (p.webkit) out.push('webkit');
  return out;
}

/**
 * Build the page as the browser will see it *after* injection: the attacker
 * markup is written into the region element once the DOM is ready (exactly as a
 * client-side render would), *then* the page's own scripts run.
 */
export function buildInjectionPage(
  html: string,
  injectInto: string,
  payload: string,
  scriptTags: string[] = [],
): string {
  const inject = `<script>
    (function(){
      var target = document.querySelector(${JSON.stringify(injectInto)});
      if (target) target.innerHTML = ${JSON.stringify(payload)};
      window.__injected = true;
    })();
  </script>`;
  const scripts = scriptTags.join('');
  const tail = inject + scripts;
  if (html.includes('</body>')) return html.replace('</body>', tail + '</body>');
  return html + tail;
}

/** A mutable mount the server reads on every request. */
interface MutableMount {
  html: string;
  scripts: Array<{ path: string; body: string; kind?: 'script' | 'module' }>;
  attackerBody: string;
}

async function servePage(
  mount: MutableMount,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0] ?? '/';
    if (path === '/attacker.js') {
      res.writeHead(200, { 'content-type': 'text/javascript' });
      res.end(mount.attackerBody);
      return;
    }
    const script = mount.scripts.find((s) => s.path === path);
    if (script) {
      res.writeHead(200, { 'content-type': 'text/javascript' });
      res.end(script.body);
      return;
    }
    if (path === '/' || path === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(mount.html);
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}/`,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

interface DriverPage {
  goto: (url: string) => Promise<void>;
  evaluate: <R>(f: () => R) => Promise<R>;
  on: (ev: string, cb: (arg: unknown) => void) => void;
}

async function withChrome<T>(exe: string, fn: (page: DriverPage) => Promise<T>): Promise<T> {
  const puppeteer = require('puppeteer-core') as typeof import('puppeteer-core');
  const browser = await puppeteer.launch({
    executablePath: exe,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  try {
    return await fn((await browser.newPage()) as unknown as DriverPage);
  } finally {
    await browser.close();
  }
}

async function withPlaywright<T>(
  browserType: 'firefox' | 'webkit',
  exe: string,
  fn: (page: DriverPage) => Promise<T>,
): Promise<T> {
  const pw = require('playwright-core') as typeof import('playwright-core');
  const launcher = pw[browserType];
  const browser = await launcher.launch({ executablePath: exe, headless: true });
  try {
    return await fn((await browser.newPage()) as unknown as DriverPage);
  } finally {
    await browser.close();
  }
}

/** Run one probe in one engine. */
export async function runProbe(
  engine: EngineName,
  mount: PageMount,
  injectInto: string,
  payloadTemplate: string,
  signalExpr: string,
): Promise<ProbeOutcome> {
  const paths = browserPaths();
  const mutable: MutableMount = {
    html: mount.html,
    scripts: mount.scripts,
    attackerBody: mount.attackerBody,
  };
  const served = await servePage(mutable);
  // Substitute the real origin so absolute attacker URLs resolve.
  const payload = payloadTemplate
    .replaceAll('ATTACKER_SCRIPT', `${served.url}attacker.js`)
    .replaceAll('ATTACKER_DIR', served.url);
  const scriptTags = mount.scripts.map((s) =>
    s.kind === 'module'
      ? `<script type="module" src="${s.path}"></script>`
      : `<script src="${s.path}"></script>`,
  );
  mutable.html = buildInjectionPage(mount.html, injectInto, payload, scriptTags);

  const pageErrors: string[] = [];
  const consoleErrors: string[] = [];

  const drive = async (page: DriverPage): Promise<ProbeOutcome> => {
    page.on('pageerror', (e: unknown) => pageErrors.push(String(e)));
    page.on('console', (m: unknown) => {
      const msg = m as { type?: () => string; text?: () => string };
      if (msg.type && msg.type() === 'error' && msg.text) consoleErrors.push(msg.text());
    });
    await page.goto(served.url);
    await new Promise((r) => setTimeout(r, 150));
    let raw: unknown = null;
    let fired = false;
    try {
      const fn = new Function(
        `try { return (${signalExpr}); } catch (e) { return 'ERR:' + e; }`,
      ) as () => unknown;
      raw = await page.evaluate(fn);
      fired = raw === true;
    } catch (e) {
      raw = `EVALERR:${String(e)}`;
    }
    return { engine, fired, pageErrors, raw, consoleErrors };
  };

  try {
    if (engine === 'chrome') {
      if (!paths.chrome) throw new Error('chrome not available');
      return await withChrome(paths.chrome, drive);
    }
    if (engine === 'firefox') {
      if (!paths.firefox) throw new Error('firefox not available');
      return await withPlaywright('firefox', paths.firefox, drive);
    }
    if (!paths.webkit) throw new Error('webkit not available');
    return await withPlaywright('webkit', paths.webkit, drive);
  } finally {
    await served.close();
  }
}
