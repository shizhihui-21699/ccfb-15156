/**
 * Engine semantics model for DOM clobbering.
 *
 * Everything in this file that describes browser behaviour is derived from live
 * measurement, not from memory. The measurements were taken in this repository
 * with Chrome 157, Firefox 142 and WebKit 26 (see `npm run probe`, which
 * regenerates `data/engine-probe.json`). Where the three engines disagree, the
 * disagreement is modelled explicitly rather than flattened to one behaviour.
 *
 * The two named-access rules below are normative (WHATWG HTML "DOM tree
 * accessors" plus the WebIDL named-properties rules), and the probes confirm
 * the engines implement them:
 *
 *  - `window` is a `[Global]` object. Its named properties live on a separate
 *    named-properties object that sits *below* the whole prototype chain, so a
 *    named element can only be reached when the name is not already a property
 *    of Window, EventTarget or Object. Window builtins are therefore safe.
 *
 *  - `document` is a legacy platform object with `[LegacyOverrideBuiltIns]`.
 *    Its named getter is consulted *before* `Document.prototype`, so a named
 *    element shadows `document.cookie`, `document.title`, even
 *    `document.getElementById` and `document.toString`. The one exception is
 *    `document.location`, which is an own `[Unforgeable]` property.
 */

export type Engine = 'chrome' | 'firefox' | 'webkit';

export const ENGINES: readonly Engine[] = ['chrome', 'firefox', 'webkit'];

/** Human-readable engine identities matching the probe run. */
export const ENGINE_LABELS: Record<Engine, string> = {
  chrome: 'Chromium 157',
  firefox: 'Firefox 142',
  webkit: 'WebKit 26 (Safari)',
};

/**
 * HTML elements whose `name` attribute contributes to *window* named access.
 * Measured: embed, form, img, object. Notably NOT a, area, input, iframe,
 * button, select, textarea.
 */
export const WINDOW_NAME_ELEMENTS: ReadonlySet<string> = new Set([
  'embed',
  'form',
  'img',
  'object',
]);

/**
 * HTML elements whose `name` attribute contributes to *document* named access.
 * Measured: embed, form, iframe, img, object. (`iframe` contributes to
 * `document` via name but resolves to a WindowProxy, not an element.)
 */
export const DOCUMENT_NAME_ELEMENTS: ReadonlySet<string> = new Set([
  'embed',
  'form',
  'iframe',
  'img',
  'object',
]);

/**
 * Elements whose *id* contributes to document named access. Per spec only
 * `object` always, and `img` when it also carries a non-empty `name`. All
 * elements' ids contribute to *window* named access.
 */
export function documentIdContributes(tagName: string, hasNonEmptyName: boolean): boolean {
  if (tagName === 'object') return true;
  if (tagName === 'img' && hasNonEmptyName) return true;
  return false;
}

/**
 * `document.location` is the single Document member that named access cannot
 * shadow: it is an own `[Unforgeable]` property. Measured identical in all
 * three engines.
 */
export const UNFORGEABLE_DOCUMENT_PROPERTIES: ReadonlySet<string> = new Set(['location']);

/**
 * A property-name classifier. `windowSafe` describes whether the name is
 * already present anywhere in the Window prototype chain (and therefore not
 * reachable through named access). `documentSafe` describes whether the name
 * is an own unforgeable property of Document.
 *
 * The concrete name sets are generated from the probe and stored in
 * `data/engine-probe.json`; this interface is what the analyzer consumes.
 */
export interface EngineBuiltins {
  engine: Engine;
  /** Property names visible on window via its own properties or prototype chain. */
  windowChain: ReadonlySet<string>;
  /** Property names visible on document via its own properties or prototype chain. */
  documentChain: ReadonlySet<string>;
  /** Own, unforgeable Document properties (currently only `location`). */
  documentOwn: ReadonlySet<string>;
}

/**
 * How a name lookup resolves in a given engine, mirroring the spec algorithms.
 *
 * `window-kind` and `document-kind` model the named-access result shape. The
 * Firefox quirk: when several elements contribute the same *id*-based window
 * name, Firefox returns the first such element (a plain element) instead of an
 * HTMLCollection. Both shapes are useful to an attacker, but they differ in
 * what the attacker can chain through, so the analyzer keeps them distinct.
 */
export type NamedAccessShape =
  | 'single-element'
  | 'html-collection'
  | 'window-proxy';

/** A contributed named object: which element is reachable and how. */
export interface NamedContribution {
  /** Attribute that supplied the name: `id` or `name`. */
  via: 'id' | 'name';
  tagName: string;
  /** `window`, `document`, or both. */
  scope: 'window' | 'document' | 'both';
  /** True when the element is reachable as a nested member of a form. */
  formListedChild: boolean;
}

/** Methods on a form that named access overrides (measured). */
export const FORM_OVERRIDABLE_PROPERTIES: ReadonlySet<string> = new Set([
  'action',
  'method',
  'submit',
  'reset',
  'enctype',
  'encoding',
  'target',
  'acceptCharset',
  'autocomplete',
  'noValidate',
  'elements',
  'length',
  'id',
  'name',
  'title',
  'className',
  'innerHTML',
]);

/**
 * Form-listed elements: a child with `name` (or `id`) becomes `form[thatName]`.
 * Measured set. NOT included: a, div, iframe, embed, label, form, span.
 */
export const FORM_LISTED_ELEMENTS: ReadonlySet<string> = new Set([
  'button',
  'fieldset',
  'img',
  'input',
  'object',
  'output',
  'select',
  'textarea',
]);

/** Elements whose stringification yields an attacker-chosen URL. */
export const URL_STRINGIFY_ELEMENTS: ReadonlySet<string> = new Set(['a', 'area']);

/**
 * Attributes that turn an element into a "source" whose `.src`, `.href`,
 * `.data`, or `.value` an attacker controls — the primitive that turns a
 * clobbered object into a hostile URL.
 */
export const SOURCE_ATTRIBUTES: Record<string, { prop: string; urlLike: boolean }> = {
  a: { prop: 'href', urlLike: true },
  area: { prop: 'href', urlLike: true },
  img: { prop: 'src', urlLike: true },
  script: { prop: 'src', urlLike: true },
  iframe: { prop: 'src', urlLike: true },
  embed: { prop: 'src', urlLike: true },
  object: { prop: 'data', urlLike: true },
  source: { prop: 'src', urlLike: true },
  video: { prop: 'src', urlLike: true },
  audio: { prop: 'src', urlLike: true },
  track: { prop: 'src', urlLike: true },
  form: { prop: 'action', urlLike: true },
  button: { prop: 'formAction', urlLike: true },
  input: { prop: 'formAction', urlLike: true },
};

/**
 * Structural version marker for the semantics tables. Bump when the measured
 * model changes so cached probe data is invalidated.
 */
export const SEMANTICS_VERSION = 3;
