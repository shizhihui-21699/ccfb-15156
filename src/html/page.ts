/**
 * HTML surface analysis.
 *
 * A real page has a fixed skeleton plus some regions whose contents an
 * attacker controls (a rich-text block, a comment list, a templated
 * attribute). This module parses the page, locates those regions, and derives
 * what an attacker is able to inject there.
 *
 * The result is deliberately conservative and explicit: every region carries
 * the set of tags and attributes it permits, and every derived "capability"
 * (can an attacker create `<form name=X>` here?) is a plain boolean that the
 * report can explain. Nothing is inferred from a tag being *possible in HTML*
 * alone.
 */

import * as parse5 from 'parse5';
import type { DefaultTreeAdapterMap } from 'parse5';

type Node = DefaultTreeAdapterMap['node'];
type Element = DefaultTreeAdapterMap['element'];
type ParentNode = DefaultTreeAdapterMap['parentNode'];

export interface SanitizerProfile {
  /** Tag names (lowercase) the region permits. `null` means no restriction. */
  allowTags: ReadonlySet<string> | null;
  /** Attribute names (lowercase) the region permits. `null` means no restriction. */
  allowAttributes: ReadonlySet<string> | null;
  /** Attributes the sanitizer always removes even if otherwise allowed. */
  denyAttributes: ReadonlySet<string>;
  /** Tags the sanitizer always removes. */
  denyTags: ReadonlySet<string>;
}

/** No sanitizer: attacker can write arbitrary markup (e.g. raw innerHTML). */
export function permissiveProfile(): SanitizerProfile {
  return {
    allowTags: null,
    allowAttributes: null,
    denyAttributes: new Set(),
    denyTags: new Set(),
  };
}

export interface InjectionRegion {
  /** Human label from the page spec (e.g. "comment-body"). */
  name: string;
  /** The element whose contents are user controlled, if satisfied by a selector. */
  element: Element | null;
  /** Selector that matched, for reporting. */
  selector: string;
  /** Markup context: element content, an attribute value, or a full template slot. */
  context: 'element-content' | 'attribute' | 'template-slot';
  /** What the attacker can write here. */
  profile: SanitizerProfile;
  /** True when the region sits inside a `<form>` element. */
  insideForm: boolean;
  /** Path of ancestor tag names (outermost first), for reporting. */
  ancestry: string[];
}

export interface PageAnalysis {
  document: Node;
  regions: InjectionRegion[];
  /** Every element in the parsed page, in tree order. */
  elements: Element[];
}

export function attr(el: Element, name: string): string | null {
  for (const a of el.attrs) if (a.name === name) return a.value;
  return null;
}

function isElement(n: Node): n is Element {
  return 'tagName' in n && typeof (n as Element).tagName === 'string';
}

function children(n: Node): Node[] {
  const parent = n as ParentNode;
  const out: Node[] = [];
  if (Array.isArray((parent as { childNodes?: Node[] }).childNodes)) {
    out.push(...((parent as { childNodes: Node[] }).childNodes));
  }
  // `<template>` keeps its children in `content`.
  const content = (n as { content?: ParentNode }).content;
  if (content && Array.isArray((content as { childNodes?: Node[] }).childNodes)) {
    out.push(...((content as { childNodes: Node[] }).childNodes));
  }
  return out;
}

/** Depth-first walk over elements in tree order. */
export function walkElements(root: Node, visit: (el: Element, ancestry: Element[]) => void): void {
  const stack: Array<{ node: Node; ancestry: Element[] }> = [{ node: root, ancestry: [] }];
  while (stack.length) {
    const { node, ancestry } = stack.pop()!;
    for (const child of children(node)) {
      if (isElement(child)) {
        visit(child, ancestry);
        stack.push({ node: child, ancestry: [...ancestry, child] });
      } else {
        stack.push({ node: child, ancestry });
      }
    }
  }
}

/** Minimal CSS selector support: `#id`, `.class`, `tag`, and combinations. */
export function matchesSimpleSelector(el: Element, selector: string): boolean {
  let tag: string | null = null;
  let id: string | null = null;
  const classes: string[] = [];
  for (const part of selector.trim().split(/(?=[#.])/)) {
    if (!part) continue;
    if (part.startsWith('#')) id = part.slice(1);
    else if (part.startsWith('.')) classes.push(part.slice(1));
    else tag = part.toLowerCase();
  }
  if (tag && el.tagName.toLowerCase() !== tag) return false;
  if (id && attr(el, 'id') !== id) return false;
  if (classes.length) {
    const have = new Set((attr(el, 'class') ?? '').split(/\s+/).filter(Boolean));
    for (const c of classes) if (!have.has(c)) return false;
  }
  return true;
}

export interface RegionSpec {
  name: string;
  /** Selector identifying the element whose *contents* the attacker controls. */
  selector: string;
  context?: InjectionRegion['context'];
  /** Sanitizer profile; defaults to permissive. */
  profile?: SanitizerProfile;
}

export interface PageSpec {
  /** Raw HTML of the page template. */
  html: string;
  regions: RegionSpec[];
}

/**
 * Parse a page and resolve its declared injection regions.
 */
export function analyzePage(spec: PageSpec): PageAnalysis {
  const document = parse5.parse(spec.html, { sourceCodeLocationInfo: true });
  const elements: Element[] = [];
  walkElements(document, (el) => elements.push(el));

  const regions: InjectionRegion[] = [];
  for (const rs of spec.regions) {
    const matches = elements.filter((el) => matchesSimpleSelector(el, rs.selector));
    if (matches.length === 0) {
      // Still record the region so the report can flag a stale selector.
      regions.push({
        name: rs.name,
        element: null,
        selector: rs.selector,
        context: rs.context ?? 'element-content',
        profile: rs.profile ?? permissiveProfile(),
        insideForm: false,
        ancestry: [],
      });
      continue;
    }
    for (const el of matches) {
      const ancestry: Element[] = [];
      walkElements(document, (e, anc) => {
        if (e === el) ancestry.push(...anc);
      });
      regions.push({
        name: rs.name,
        element: el,
        selector: rs.selector,
        context: rs.context ?? 'element-content',
        profile: rs.profile ?? permissiveProfile(),
        insideForm: ancestry.some((a) => a.tagName.toLowerCase() === 'form'),
        ancestry: ancestry.map((a) => a.tagName.toLowerCase()),
      });
    }
  }

  return { document, regions, elements };
}

/** Does the region permit this tag and (optionally) this attribute? */
export function regionPermits(
  region: InjectionRegion,
  tagName: string,
  attribute?: string,
): boolean {
  const tag = tagName.toLowerCase();
  const p = region.profile;
  if (p.denyTags.has(tag)) return false;
  if (p.allowTags && !p.allowTags.has(tag)) return false;
  if (attribute !== undefined) {
    const a = attribute.toLowerCase();
    if (p.denyAttributes.has(a)) return false;
    if (p.allowAttributes && !p.allowAttributes.has(a)) return false;
  }
  return true;
}
