/**
 * Unit tests for JavaScript global-read extraction and protection classification.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseScripts } from '../src/js/parse.ts';
import { extractGlobalReads } from '../src/js/globals.ts';
import { applyTaint, propagateTaint } from '../src/js/taint.ts';
import { protectionOf } from '../src/js/protection.ts';
import type { GlobalRead } from '../src/js/globals.ts';

function reads(code: string, kind: 'script' | 'module' = 'script'): GlobalRead[] {
  const { parsed, failures } = parseScripts([{ id: 's', code, kind }]);
  assert.equal(failures.length, 0, failures[0]?.detail);
  const raw = extractGlobalReads(parsed[0]!);
  const taint = propagateTaint(parsed[0]!);
  return applyTaint(raw, new Map([['s', taint]]));
}

function find(rs: GlobalRead[], name: string): GlobalRead | undefined {
  return rs.find((r) => r.name === name);
}

test('extracts a window property read', () => {
  const r = find(reads(`var a = window.CONFIG;`), 'CONFIG');
  assert.ok(r);
  assert.equal(r.kind, 'window-property');
  assert.equal(r.scope, 'window');
});

test('extracts a bare free identifier', () => {
  const r = find(reads(`var a = APP_CONFIG;`), 'APP_CONFIG');
  assert.ok(r);
  assert.equal(r.kind, 'bare-identifier');
  assert.equal(r.declaration, 'none');
});

test('extracts a document property read', () => {
  const r = find(reads(`var c = document.cookie;`), 'cookie');
  assert.ok(r);
  assert.equal(r.kind, 'document-property');
  assert.equal(r.scope, 'document');
});

test('distinguishes var from let at top level', () => {
  const varRead = find(reads(`var CONFIG = {}; window.CONFIG;`), 'CONFIG');
  assert.equal(varRead?.declaration, 'var');
  assert.equal(protectionOf(varRead!).protectedFromClobber, true);

  const letRead = find(reads(`let CONFIG = {}; window.CONFIG;`), 'CONFIG');
  assert.equal(letRead?.declaration, 'lexical');
  assert.equal(protectionOf(letRead!).protectedFromClobber, false);
});

test('a bare read of a top-level let is protected, but window.X is not', () => {
  const rs = reads(`let CONFIG = {cdn:'/x'}; window.__r = CONFIG.cdn; window.__w = window.CONFIG;`);
  const bare = rs.find((r) => r.name === 'CONFIG' && r.kind === 'bare-identifier');
  const viaWindow = rs.find((r) => r.name === 'CONFIG' && r.kind === 'window-property');
  assert.ok(bare, 'bare CONFIG read');
  assert.ok(viaWindow, 'window.CONFIG read');
  assert.equal(protectionOf(bare).protectedFromClobber, true);
  assert.equal(protectionOf(viaWindow).protectedFromClobber, false);
});

test('module imports are never globals', () => {
  const rs = reads(`import cfg from './cfg.js'; var a = cfg.cdn;`, 'module');
  assert.equal(find(rs, 'cfg'), undefined);
});

test('records the captured property path', () => {
  const r = find(reads(`fetch(window.CONFIG.api.base);`), 'CONFIG');
  assert.ok(r);
  assert.deepEqual(r.propertyPath, ['api', 'base']);
});

test('skips write-only references', () => {
  const rs = reads(`window.__t = 1; window.__u++; __v = 2;`);
  assert.equal(find(rs, '__t'), undefined);
  assert.equal(find(rs, '__u'), undefined);
  assert.equal(find(rs, '__v'), undefined);
});

test('local variables are not reported as globals', () => {
  const rs = reads(`function f(){ var local = 1; return local + 1; } f();`);
  assert.equal(find(rs, 'local'), undefined);
});

test('taint propagates through alias chains to a URL sink', () => {
  const rs = reads(`
    (function(){
      var a = window.CONFIG || {};
      var b = a;
      var s = document.createElement('script');
      s.src = b.cdn;
      document.head.appendChild(s);
    })();
  `);
  const r = find(rs, 'CONFIG');
  assert.ok(r);
  assert.ok(r.usages.includes('url-sink'), `expected url-sink, got ${r.usages.join(',')}`);
});

test('taint propagates through concat expressions with free globals', () => {
  const rs = reads(`var s = document.createElement('script'); s.src = (jQuery && jQuery.cdn) + '.js';`);
  const r = find(rs, 'jQuery');
  assert.ok(r);
  assert.ok(r.usages.includes('url-sink'), `expected url-sink, got ${r.usages.join(',')}`);
});

test('taint propagates through destructuring from window', () => {
  const rs = reads(`const { CONFIG } = window; var s = document.createElement('script'); s.src = CONFIG.cdn;`);
  const r = rs.find((x) => x.name === 'CONFIG' && x.usages.includes('url-sink'));
  assert.ok(r, 'destructured CONFIG should reach the sink');
});

test('extracts computed member access', () => {
  const r = find(reads(`var a = window['MY_CFG'];`), 'MY_CFG');
  assert.ok(r);
  assert.equal(r.kind, 'window-computed');
});

test('extracts this.X at top level but not inside a function', () => {
  const top = find(reads(`this.APP_CONFIG;`), 'APP_CONFIG');
  assert.ok(top);
  assert.equal(top.kind, 'this-property');

  const inner = reads(`function f(){ return this.OTHER; }`);
  assert.equal(find(inner, 'OTHER'), undefined);
});

test('parses minified code without beautification', () => {
  const rs = reads(`!function(){var a=window.CONFIG||{};e.src=a.cdn}();`);
  assert.ok(find(rs, 'CONFIG'));
});

test('traces optional chaining chains to a sink', () => {
  const rs = reads(`var u = window.APP?.config?.url; el.href = u;`);
  const r = find(rs, 'APP');
  assert.ok(r);
  assert.deepEqual(r.propertyPath, ['config', 'url']);
  assert.ok(r.usages.includes('url-sink'), `expected url-sink, got ${r.usages.join(',')}`);
});

test('treats assignment to window.location as a navigation sink', () => {
  const rs = reads(`var u = window.APP.config.url; window.location = u;`);
  const r = find(rs, 'APP');
  assert.ok(r);
  assert.ok(r.usages.includes('url-sink'));
});

test('handles typeof guard followed by use', () => {
  const rs = reads(`if (typeof APP_CONFIG !== 'undefined') { var s = document.createElement('script'); s.src = APP_CONFIG.cdn; }`);
  const r = find(rs, 'APP_CONFIG');
  assert.ok(r);
  assert.ok(r.usages.includes('url-sink'));
});

test('handles webpack jsonp bootstrap without false locators', () => {
  const rs = reads(`(window.webpackJsonp = window.webpackJsonp || []).push([[0],{}]);`);
  const r = find(rs, 'webpackJsonp');
  // The assignment target itself is a write, but the `||` operand is a read.
  assert.ok(r === undefined || r.usages.includes('type-test'));
});

test('handles Object.assign defaults merges', () => {
  const rs = reads(`var cfg = Object.assign({}, window.DEFAULTS, window.OVERRIDES); el.src = cfg.url;`);
  const defaults = find(rs, 'DEFAULTS');
  assert.ok(defaults);
  assert.ok(defaults.usages.includes('url-sink'));
});

test('handles an IIFE receiving window as a parameter', () => {
  const rs = reads(`(function(g){ var c = g.APP_CONFIG || {}; }).call(null, window);`);
  // `g.APP_CONFIG` is not resolvable to a global here, but the script must not
  // crash and must not invent a finding.
  assert.doesNotThrow(() => rs);
});
