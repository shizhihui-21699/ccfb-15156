/**
 * Unit tests for the engine-semantics model: the measured reachability rules.
 *
 * These encode the behaviour verified against real browsers in e2e/, so a
 * change to the model that disagrees with the engines fails here first.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { loadEngineBuiltins } from '../src/model/builtins.ts';
import { nameReachability, reachabilityByEngine, multiContributorShape } from '../src/model/reachability.ts';
import {
  DOCUMENT_NAME_ELEMENTS,
  WINDOW_NAME_ELEMENTS,
  documentIdContributes,
} from '../src/model/engine-semantics.ts';

const builtins = loadEngineBuiltins();

test('window builtins are not reachable in any engine', () => {
  for (const engine of ['chrome', 'firefox', 'webkit'] as const) {
    for (const name of ['fetch', 'location', 'document', 'name', 'top', 'toString', 'addEventListener']) {
      const r = nameReachability('window', name, builtins[engine]);
      assert.equal(r.reachable, false, `${engine}: window.${name} should be protected`);
    }
  }
});

test('free window names are reachable in every engine', () => {
  for (const engine of ['chrome', 'firefox', 'webkit'] as const) {
    for (const name of ['APP_CONFIG', 'CONFIG', 'jQuery', 'gapi']) {
      const r = nameReachability('window', name, builtins[engine]);
      assert.equal(r.reachable, true, `${engine}: window.${name} should be clobberable`);
    }
  }
});

test('document prototype members are shadowable', () => {
  for (const engine of ['chrome', 'firefox', 'webkit'] as const) {
    for (const name of ['cookie', 'title', 'getElementById', 'createElement', 'toString']) {
      const r = nameReachability('document', name, builtins[engine]);
      assert.equal(r.reachable, true, `${engine}: document.${name} should be shadowable`);
    }
  }
});

test('document.location is unforgeable everywhere', () => {
  for (const engine of ['chrome', 'firefox', 'webkit'] as const) {
    const r = nameReachability('document', 'location', builtins[engine]);
    assert.equal(r.reachable, false, `${engine}: document.location must be protected`);
    assert.equal(r.reason, 'unforgeable');
  }
});

test('window name-element set matches the spec', () => {
  assert.deepEqual([...WINDOW_NAME_ELEMENTS].sort(), ['embed', 'form', 'img', 'object']);
  for (const tag of ['a', 'area', 'input', 'iframe', 'div']) {
    assert.equal(WINDOW_NAME_ELEMENTS.has(tag), false, `${tag} must not contribute a name to window`);
  }
});

test('document name-element set matches the spec', () => {
  assert.deepEqual([...DOCUMENT_NAME_ELEMENTS].sort(), ['embed', 'form', 'iframe', 'img', 'object']);
});

test('document id contribution is limited to object and name-carrying img', () => {
  assert.equal(documentIdContributes('object', false), true);
  assert.equal(documentIdContributes('img', true), true);
  assert.equal(documentIdContributes('img', false), false);
  assert.equal(documentIdContributes('form', true), false);
  assert.equal(documentIdContributes('div', true), false);
});

test('Firefox returns a single element for multiple id contributors; Chromium/WebKit a collection', () => {
  const twoIds = [
    { via: 'id' as const },
    { via: 'id' as const },
  ];
  assert.equal(multiContributorShape('firefox', twoIds), 'single-element');
  assert.equal(multiContributorShape('chrome', twoIds), 'html-collection');
  assert.equal(multiContributorShape('webkit', twoIds), 'html-collection');

  const twoNames = [
    { via: 'name' as const },
    { via: 'name' as const },
  ];
  assert.equal(multiContributorShape('firefox', twoNames), 'html-collection');

  assert.equal(multiContributorShape('chrome', [{ via: 'id' }]), 'single-element');
});

test('reachabilityByEngine reports all three', () => {
  const r = reachabilityByEngine('window', 'CFG', builtins);
  assert.equal(Object.keys(r).length, 3);
  assert.ok(r.chrome.reachable && r.firefox.reachable && r.webkit.reachable);
});
