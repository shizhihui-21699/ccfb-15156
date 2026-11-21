/**
 * Injection modelling: what element can an attacker actually place, for a given
 * name, in a given injection region, and what does that element expose?
 *
 * The analyzer does not assume "any name is injectable". It enumerates the
 * concrete element shapes a region permits and, crucially, what the resulting
 * value *is* when the page reads it. That last part is easy to get wrong and is
 * the difference between a real finding and noise:
 *
 *   - `<form id=X><input name=Y value=URL>` makes `String(X.Y)` the string
 *     `[object HTMLInputElement]`, NOT the URL. A page doing `s.src = cfg.cdn`
 *     loads a garbage URL and fails; the value is attacker-*influenced* only if
 *     the page reads `.value` explicitly.
 *   - `<form id=X><img name=Y src=URL>` makes `X.Y.src` the URL, and
 *     `String(X.Y)` the string `[object HTMLImageElement]`. This works only for
 *     pages that read the `.src` property.
 *   - `<a id=X href=URL>` makes `String(X)` the URL directly, so
 *     `s.src = CONFIG + ''` is a real takeover.
 *
 * Each plan therefore records both the element chain and *how the attacker's
 * value becomes observable* (`String(value)` vs `.prop`).
 */

import type { InjectionRegion } from '../html/page.ts';
import { regionPermits } from '../html/page.ts';
import {
  DOCUMENT_NAME_ELEMENTS,
  FORM_LISTED_ELEMENTS,
  URL_STRINGIFY_ELEMENTS,
  WINDOW_NAME_ELEMENTS,
  documentIdContributes,
} from '../model/engine-semantics.ts';
import type { Engine } from '../model/engine-semantics.ts';
import { multiContributorShape, nameReachability } from '../model/reachability.ts';
import type { EngineBuiltins } from '../model/engine-semantics.ts';

/** The purpose an injected element serves. */
export type Role =
  | 'name-carrier' // supplies the clobbered name through id or name
  | 'url-carrier' // supplies a hostile URL through href/src/data
  | 'nested-source'; // sits inside a form so it becomes form[childName]

/**
 * How the attacker's value becomes observable to the page.
 *
 *  - `string`   : `String(X)` yields the attacker URL (anchor/area href)
 *  - `property` : `X.prop` yields the attacker URL (img.src, a.href, ...)
 *  - `text`     : only `.value`/`.textContent` yields the value (input/button);
 *                 the page must read that property explicitly
 */
export type ValueChannel = 'string' | 'property' | 'text';

export interface InjectedElement {
  role: Role;
  tagName: string;
  /** Attribute that carries the clobbered name. */
  nameAttribute: 'id' | 'name';
  /** Property that yields the attacker value, when relevant. */
  valueProperty?: string;
  /** For a nested source, the name it must carry inside the parent form. */
  nestedName?: string;
  /** Human description for the report. */
  describe(): string;
}

export interface InjectionPlan {
  /** The chain of elements that must be injected, outermost first. */
  elements: InjectedElement[];
  /** Region that supplies them. */
  region: InjectionRegion;
  /** How the page must read the value for the attack to work. */
  channel: ValueChannel;
  /** The property the page must read, for `property`/`text` channels. */
  requiredProperty?: string;
  /** Every element in the plan is permitted by the region's sanitizer. */
  permitted: boolean;
  /** Reasons this plan is not permitted, when it is not. */
  blockers: string[];
}

/**
 * Window-name property that a page read must target for a nested `text`
 * channel to yield a usable string. For an input, `X.value` is the attacker
 * string; `X.src` is empty.
 */
const TEXT_CHANNEL_PROPERTIES = new Set(['value', 'textContent', 'innerHTML', 'text']);

/**
 * For a nested form child, does the read path ask for a property this element
 * actually supplies a hostile value through?
 *
 * This is the check that keeps the analyzer honest. `nestedUrlPlans` is only
 * useful when the page reads `CONFIG.cdn.src` (an `<img>` child) or
 * `CONFIG.cdn.value` (an `<input>` child). A page doing `s.src = CONFIG.cdn`
 * reads the *element*, whose string form is `[object ...]`, so it does not load
 * the attacker URL.
 */
export function nestedReadMatchesChild(
  readPropertyPath: readonly string[],
  childTag: string,
): { matches: boolean; channel: ValueChannel; requiredProperty?: string } {
  // The read path is, e.g., ['cdn', 'src'] for `CONFIG.cdn.src`, where 'cdn' is
  // the child name and 'src' is the property fetched from the child element.
  const finalProp = readPropertyPath.length >= 2 ? readPropertyPath[readPropertyPath.length - 1] : undefined;
  if (!finalProp) {
    return { matches: false, channel: 'string' };
  }
  if (childTag === 'img' && finalProp === 'src') {
    return { matches: true, channel: 'property', requiredProperty: 'src' };
  }
  if ((childTag === 'a' || childTag === 'area') && finalProp === 'href') {
    return { matches: true, channel: 'property', requiredProperty: 'href' };
  }
  if (childTag === 'object' && finalProp === 'data') {
    return { matches: true, channel: 'property', requiredProperty: 'data' };
  }
  if (
    (childTag === 'input' || childTag === 'button' || childTag === 'textarea' || childTag === 'select') &&
    TEXT_CHANNEL_PROPERTIES.has(finalProp)
  ) {
    return { matches: true, channel: 'text', requiredProperty: finalProp };
  }
  if (childTag === 'form' && finalProp === 'action') {
    return { matches: true, channel: 'property', requiredProperty: 'action' };
  }
  return { matches: false, channel: 'property' };
}

function windowNameCarriers(region: InjectionRegion, name: string): InjectedElement[] {
  const out: InjectedElement[] = [];
  for (const tag of ['div', 'span', 'p']) {
    if (regionPermits(region, tag) && regionPermits(region, tag, 'id')) {
      out.push({
        role: 'name-carrier',
        tagName: tag,
        nameAttribute: 'id',
        describe: () => `<${tag} id="${name}">`,
      });
      break;
    }
  }
  for (const tag of ['form', 'img', 'embed', 'object']) {
    if (!WINDOW_NAME_ELEMENTS.has(tag)) continue;
    if (regionPermits(region, tag) && regionPermits(region, tag, 'name')) {
      out.push({
        role: 'name-carrier',
        tagName: tag,
        nameAttribute: 'name',
        describe: () => `<${tag} name="${name}">`,
      });
    }
  }
  return out;
}

function documentNameCarriers(region: InjectionRegion, name: string): InjectedElement[] {
  const out: InjectedElement[] = [];
  for (const tag of ['form', 'img', 'embed', 'object', 'iframe']) {
    if (!DOCUMENT_NAME_ELEMENTS.has(tag)) continue;
    if (regionPermits(region, tag) && regionPermits(region, tag, 'name')) {
      out.push({
        role: 'name-carrier',
        tagName: tag,
        nameAttribute: 'name',
        describe: () => `<${tag} name="${name}">`,
      });
    }
  }
  if (regionPermits(region, 'object') && regionPermits(region, 'object', 'id')) {
    out.push({
      role: 'name-carrier',
      tagName: 'object',
      nameAttribute: 'id',
      describe: () => `<object id="${name}">`,
    });
  }
  return out;
}

/**
 * Enumerate the simplest injection plans that make a bare name reachable.
 * These supply an element; a page that only tests `if (window.X)` or reads a
 * string property is affected. They do NOT claim to supply a URL by
 * themselves — that is `nestedUrlPlans` and `stringUrlPlans`.
 */
export function injectionPlansForName(
  name: string,
  scope: 'window' | 'document',
  region: InjectionRegion,
  builtins: Record<Engine, EngineBuiltins>,
): InjectionPlan[] {
  const carriers = scope === 'window' ? windowNameCarriers(region, name) : documentNameCarriers(region, name);
  void builtins;
  return carriers.map((carrier) => ({
    elements: [carrier],
    region,
    channel: 'property' as ValueChannel,
    permitted: true,
    blockers: [],
  }));
}

/**
 * Plans that make `String(name)` an attacker URL, via an anchor or area whose
 * href the attacker sets. This is what makes `s.src = CONFIG + ''` exploitable.
 */
export function stringUrlPlans(
  name: string,
  region: InjectionRegion,
): InjectionPlan[] {
  const plans: InjectionPlan[] = [];
  for (const tag of ['a', 'area']) {
    if (!URL_STRINGIFY_ELEMENTS.has(tag)) continue;
    if (!regionPermits(region, tag)) continue;
    if (!regionPermits(region, tag, 'id') || !regionPermits(region, tag, 'href')) continue;
    plans.push({
      elements: [
        {
          role: 'url-carrier',
          tagName: tag,
          nameAttribute: 'id',
          valueProperty: 'href',
          describe: () => `<${tag} id="${name}" href="https://attacker/">`,
        },
      ],
      region,
      channel: 'string',
      permitted: true,
      blockers: [],
    });
  }
  return plans;
}

/**
 * Plans that make a *nested* read of the clobbered name yield an attacker URL.
 *
 * `propertyPath` is the path the page reads after the name, e.g. `['cdn']` for
 * `CONFIG.cdn` or `['cdn', 'src']` for `CONFIG.cdn.src`. A plan only qualifies
 * if the child element supplies the value through exactly the property the page
 * reads — see `nestedReadMatchesChild`.
 */
export function nestedUrlPlans(
  rootName: string,
  propertyPath: readonly string[],
  region: InjectionRegion,
  engines: readonly Engine[],
): InjectionPlan[] {
  void engines;
  if (propertyPath.length === 0) return [];
  const childName = propertyPath[0]!;
  const plans: InjectionPlan[] = [];

  if (!regionPermits(region, 'form') || !regionPermits(region, 'form', 'id')) return plans;

  for (const childTag of FORM_LISTED_ELEMENTS) {
    if (!regionPermits(region, childTag)) continue;
    const match = nestedReadMatchesChild(propertyPath, childTag);
    if (!match.matches) continue;

    // The child needs the property name; prefer `name`, fall back to `id`.
    const nameAttr: 'name' | 'id' = regionPermits(region, childTag, 'name') ? 'name' : 'id';
    if (nameAttr === 'id' && !regionPermits(region, childTag, 'id')) continue;

    // The attribute that carries the hostile value.
    const valueAttr =
      childTag === 'img' ? 'src'
      : childTag === 'a' || childTag === 'area' ? 'href'
      : childTag === 'object' ? 'data'
      : childTag === 'form' ? 'action'
      : 'value';
    if (!regionPermits(region, childTag, valueAttr)) continue;

    plans.push({
      elements: [
        {
          role: 'name-carrier',
          tagName: 'form',
          nameAttribute: 'id',
          describe: () => `<form id="${rootName}">`,
        },
        {
          role: 'nested-source',
          tagName: childTag,
          nameAttribute: nameAttr,
          valueProperty: match.requiredProperty,
          nestedName: childName,
          describe: () => `<${childTag} ${nameAttr}="${childName}" ${valueAttr}="https://attacker/">`,
        },
      ],
      region,
      channel: match.channel,
      ...(match.requiredProperty ? { requiredProperty: match.requiredProperty } : {}),
      permitted: true,
      blockers: [],
    });
    break; // one child shape is enough
  }
  return plans;
}

/**
 * Whether several elements contributing to the same window name still let a
 * nested property be reached. Firefox returns the first id contributor as a
 * plain element, so nesting survives there but not in Chrome/WebKit, where an
 * HTMLCollection has no such property.
 */
export function multiElementAnalysis(
  contributors: ReadonlyArray<{ via: 'id' | 'name' }>,
  engines: readonly Engine[],
): { nestedWorksIn: Engine[]; nestedFailsIn: Engine[] } {
  const nestedWorksIn: Engine[] = [];
  const nestedFailsIn: Engine[] = [];
  for (const engine of engines) {
    const shape = multiContributorShape(engine, contributors);
    if (shape === 'single-element') nestedWorksIn.push(engine);
    else nestedFailsIn.push(engine);
  }
  return { nestedWorksIn, nestedFailsIn };
}

export function documentNameReachableByShape(
  tag: string,
  nameAttribute: 'id' | 'name',
  hasNameAttribute: boolean,
): boolean {
  if (nameAttribute === 'name') return DOCUMENT_NAME_ELEMENTS.has(tag);
  return documentIdContributes(tag, hasNameAttribute);
}

export function nameReachableInEngines(
  scope: 'window' | 'document',
  name: string,
  engines: readonly Engine[],
  builtins: Record<Engine, EngineBuiltins>,
): Engine[] {
  const out: Engine[] = [];
  for (const engine of engines) {
    const r = nameReachability(scope, name, builtins[engine]);
    if (r.reachable) out.push(engine);
  }
  return out;
}
