/**
 * Injection modelling: what element can an attacker actually place, for a given
 * name, in a given injection region, and what does that element expose?
 *
 * The analyzer does not assume "any name is injectable". It enumerates the
 * concrete element shapes a region permits and reports the smallest shape that
 * supplies a given name.
 */

import type { InjectionRegion } from '../html/page.ts';
import { regionPermits } from '../html/page.ts';
import {
  DOCUMENT_NAME_ELEMENTS,
  FORM_LISTED_ELEMENTS,
  SOURCE_ATTRIBUTES,
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
  | 'url-carrier' // supplies a hostile URL through href/src/data/value
  | 'nested-source'; // sits inside a form so it becomes form[childName]

export interface InjectedElement {
  role: Role;
  tagName: string;
  /** Attribute that carries the clobbered name. */
  nameAttribute: 'id' | 'name';
  /** Attribute carrying a hostile value, when the role is a URL carrier. */
  sourceAttribute?: string;
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
  /** Every element in the plan is permitted by the region's sanitizer. */
  permitted: boolean;
  /** Reasons this plan is not permitted, when it is not. */
  blockers: string[];
}

function canUseTag(region: InjectionRegion, tag: string): boolean {
  return regionPermits(region, tag);
}

function canUseAttr(region: InjectionRegion, tag: string, attr: string): boolean {
  return regionPermits(region, tag, attr);
}

/**
 * Enumerate the simplest ways to supply a *window* name in a region.
 *
 * Strategies, weakest-markup first:
 *  1. `<div id=X>` — any tag with the id; cheapest and always works.
 *  2. `<form name=X>` / `<img name=X>` — name-based, needs the tag allowed.
 */
function windowNameCarriers(region: InjectionRegion, name: string): InjectedElement[] {
  const out: InjectedElement[] = [];
  // A generic element with an id. `div` is the least suspicious carrier.
  for (const tag of ['div', 'span', 'p']) {
    if (canUseTag(region, tag) && canUseAttr(region, tag, 'id')) {
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
    if (canUseTag(region, tag) && canUseAttr(region, tag, 'name')) {
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

/** Enumerate ways to supply a *document* name in a region. */
function documentNameCarriers(region: InjectionRegion, name: string): InjectedElement[] {
  const out: InjectedElement[] = [];
  for (const tag of ['form', 'img', 'embed', 'object', 'iframe']) {
    if (!DOCUMENT_NAME_ELEMENTS.has(tag)) continue;
    if (canUseTag(region, tag) && canUseAttr(region, tag, 'name')) {
      out.push({
        role: 'name-carrier',
        tagName: tag,
        nameAttribute: 'name',
        describe: () => `<${tag} name="${name}">`,
      });
    }
  }
  // `object` and (name-carrying) `img` also contribute through id.
  if (canUseTag(region, 'object') && canUseAttr(region, 'object', 'id')) {
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
 * Given a clobbered name and an injection region, enumerate the simplest
 * injection plans that make the name reachable in *every* engine. Plans that
 * only work in some engines are returned with `permitted` true but flagged via
 * the caller's engine list.
 */
export function injectionPlansForName(
  name: string,
  scope: 'window' | 'document',
  region: InjectionRegion,
  builtins: Record<Engine, EngineBuiltins>,
): InjectionPlan[] {
  const carriers = scope === 'window' ? windowNameCarriers(region, name) : documentNameCarriers(region, name);
  const plans: InjectionPlan[] = [];
  for (const carrier of carriers) {
    plans.push({
      elements: [carrier],
      region,
      permitted: true,
      blockers: [],
    });
  }
  // Note reachability constraints are applied by the analyzer, which knows the
  // engine set it is reporting for.
  void builtins;
  return plans;
}

/**
 * Can the region supply a URL for this name, so that a read like
 * `CONFIG.cdn.src` yields an attacker URL? This models the nested clobbering
 * used by real exploits: a form (or a single anchor) whose child bears the
 * expected property name.
 *
 * Returns the elements required, or null when the region cannot express it.
 */
export function nestedUrlPlans(
  rootName: string,
  propertyPath: readonly string[],
  region: InjectionRegion,
  engines: readonly Engine[],
): InjectionPlan[] {
  if (propertyPath.length === 0) return [];
  const childName = propertyPath[0]!;
  const plans: InjectionPlan[] = [];

  // Strategy A: a form root with a listed child carrying the property name.
  // The child's own value/src/href supplies the URL. This is the classic
  // `window.CONFIG.cdn.src` chain.
  if (canUseTag(region, 'form') && canUseAttr(region, 'form', 'id')) {
    for (const childTag of FORM_LISTED_ELEMENTS) {
      if (!canUseTag(region, childTag)) continue;
      const source = SOURCE_ATTRIBUTES[childTag];
      if (!source) continue;
      const nameAttr: 'name' | 'id' = canUseAttr(region, childTag, 'name') ? 'name' : 'id';
      if (nameAttr === 'id' && !canUseAttr(region, childTag, 'id')) continue;
      if (!canUseAttr(region, childTag, source.prop.toLowerCase()) &&
          !canUseAttr(region, childTag, source.prop === 'formAction' ? 'formaction' : source.prop)) {
        continue;
      }
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
            sourceAttribute: source.prop,
            nestedName: childName,
            describe: () => `<${childTag} ${nameAttr}="${childName}" ${source.prop}="https://attacker/">`,
          },
        ],
        region,
        permitted: true,
        blockers: [],
      });
      break;
    }
  }

  // Strategy B: a single anchor/area whose href supplies the URL and whose
  // stringification yields it. Works for `String(CONFIG)` and `CONFIG + ''`.
  for (const tag of ['a', 'area']) {
    if (!URL_STRINGIFY_ELEMENTS.has(tag)) continue;
    if (!canUseTag(region, tag)) continue;
    if (!canUseAttr(region, tag, 'id') || !canUseAttr(region, tag, 'href')) continue;
    plans.push({
      elements: [
        {
          role: 'url-carrier',
          tagName: tag,
          nameAttribute: 'id',
          sourceAttribute: 'href',
          describe: () => `<${tag} id="${rootName}" href="https://attacker/">`,
        },
      ],
      region,
      permitted: true,
      blockers: [],
    });
  }

  void engines;
  return plans;
}

/**
 * Given several elements contributing to the same window name, does the
 * resulting shape still let a nested property be reached? Firefox returns the
 * first id contributor as a plain element, so nesting survives there but not in
 * Chrome/WebKit, where an HTMLCollection has no such property.
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

/**
 * Whether a document-scoped name can be delivered by the region using the
 * name/id rules, checking the `img` id-with-name special case.
 */
export function documentNameReachableByShape(
  tag: string,
  nameAttribute: 'id' | 'name',
  hasNameAttribute: boolean,
): boolean {
  if (nameAttribute === 'name') return DOCUMENT_NAME_ELEMENTS.has(tag);
  return documentIdContributes(tag, hasNameAttribute);
}

/** Reachability of a name across engines, for planning purposes. */
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
