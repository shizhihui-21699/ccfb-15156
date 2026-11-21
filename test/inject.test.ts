/**
 * Unit tests for injection planning: what an attacker can build in a given
 * region, and whether a plan's value channel matches the page's read.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyzePage } from '../src/html/page.ts';
import type { InjectionRegion, SanitizerProfile } from '../src/html/page.ts';
import { PROFILES } from '../src/html/profiles.ts';
import {
  injectionPlansForName,
  nestedReadMatchesChild,
  nestedUrlPlans,
  stringUrlPlans,
} from '../src/analysis/inject.ts';
import { loadEngineBuiltins } from '../src/model/builtins.ts';

const builtins = loadEngineBuiltins();

function region(profile: SanitizerProfile): InjectionRegion {
  const page = analyzePage({
    html: '<!doctype html><html><body><div id="sink"></div></body></html>',
    regions: [{ name: 'sink', selector: '#sink', profile }],
  });
  const r = page.regions[0];
  assert.ok(r, 'region resolved');
  return r;
}

test('a permissive region can supply any window name', () => {
  const plans = injectionPlansForName('APP_CONFIG', 'window', region(PROFILES.unsafeInnerHtml()), builtins);
  assert.ok(plans.length > 0);
  const markup = plans.map((p) => p.elements[0]!.describe()).join(' ');
  assert.ok(markup.includes('APP_CONFIG'));
});

test('a region stripping id/name cannot supply a name', () => {
  const plans = injectionPlansForName('APP_CONFIG', 'window', region(PROFILES.strictNoIdName()), builtins);
  assert.equal(plans.length, 0);
});

test('a rich-text region can supply a name on img but not on form', () => {
  const plans = injectionPlansForName('APP_CONFIG', 'window', region(PROFILES.richText()), builtins);
  const tags = plans.map((p) => p.elements[0]!.tagName);
  assert.ok(tags.includes('img'), 'img[name] permitted');
  assert.equal(tags.includes('form'), false, 'form denied by richText');
});

test('an anchor supplies a string channel', () => {
  const plans = stringUrlPlans('SCRIPT_BASE', region(PROFILES.unsafeInnerHtml()));
  assert.ok(plans.length > 0);
  assert.equal(plans[0]!.channel, 'string');
});

test('nested read matches only the right child property', () => {
  // CONFIG.cdn.src → an img child supplies .src
  assert.equal(nestedReadMatchesChild(['cdn', 'src'], 'img').matches, true);
  // CONFIG.cdn.value → an input child supplies .value
  assert.equal(nestedReadMatchesChild(['cdn', 'value'], 'input').matches, true);
  // CONFIG.cdn (bare) → no child supplies a usable URL
  assert.equal(nestedReadMatchesChild(['cdn'], 'input').matches, false);
  // CONFIG.cdn.href → an anchor is not a form-listed child, so no plan here
  assert.equal(nestedReadMatchesChild(['cdn', 'value'], 'img').matches, false);
});

test('nested plan uses an img child for a .src read', () => {
  const plans = nestedUrlPlans('APP_CONFIG', ['cdn', 'src'], region(PROFILES.unsafeInnerHtml()), ['chrome']);
  assert.ok(plans.length > 0);
  const child = plans[0]!.elements[1]!;
  assert.equal(child.tagName, 'img');
  assert.equal(plans[0]!.channel, 'property');
});

test('nested plan is not produced for a bare nested read', () => {
  // `s.src = CONFIG.cdn` reads the element, whose string form is not a URL;
  // the model must not claim a takeover plan.
  const plans = nestedUrlPlans('CONFIG', ['cdn'], region(PROFILES.unsafeInnerHtml()), ['chrome']);
  assert.equal(plans.length, 0);
});

test('nested plan respects sanitizer deny-lists', () => {
  // richText allows img but denies form, so no form-rooted plan exists.
  const plans = nestedUrlPlans('CONFIG', ['cdn', 'src'], region(PROFILES.richText()), ['chrome']);
  assert.equal(plans.length, 0);
});
