/**
 * Sanitizer profiles for injection regions.
 *
 * These model what a region lets an attacker write. They are declared by the
 * page spec (or chosen from presets here) rather than guessed, because the
 * entire exploitability decision depends on them: a rich-text sanitizer that
 * permits `name` on `img` yields a clobbering primitive, while one that strips
 * every `id`/`name` does not.
 *
 * The presets approximate widely deployed configurations. They are advisory:
 * a page spec should override them with the exact allowlist the application
 * uses when that is known.
 */

import type { SanitizerProfile } from './page.ts';

/**
 * The HTML elements whose `id`/`name` can contribute to named access. If a
 * sanitizer allows any of these to keep a user-supplied id/name and the region
 * is not stripped of the attribute, the region is a clobbering surface.
 */
const NAMED_ACCESS_TAGS = [
  'a',
  'area',
  'embed',
  'form',
  'iframe',
  'img',
  'object',
] as const;

/** Attributes that matter for clobbering. */
const NAMED_ACCESS_ATTRS = ['id', 'name', 'href', 'src', 'data', 'action', 'formaction'] as const;

function set(xs: readonly string[]): ReadonlySet<string> {
  return new Set(xs.map((x) => x.toLowerCase()));
}

/**
 * A strict sanitizer that removes every attribute capable of contributing to
 * named access. This is the "safe" configuration: rich text that renders tags
 * but never lets the attacker choose an id or name.
 */
export function strictNoIdNameProfile(): SanitizerProfile {
  return {
    allowTags: null,
    allowAttributes: null,
    denyAttributes: set(['id', 'name']),
    denyTags: new Set(),
  };
}

/**
 * A typical rich-text profile: formatting and media tags, but no interactive
 * containers. `name` survives on `img` in many real sanitizer configurations,
 * which is enough to clobber `window.<name>`.
 */
export function richTextProfile(): SanitizerProfile {
  return {
    allowTags: set([
      'a',
      'b',
      'blockquote',
      'br',
      'code',
      'em',
      'i',
      'img',
      'li',
      'ol',
      'p',
      'pre',
      's',
      'span',
      'strong',
      'sub',
      'sup',
      'u',
      'ul',
    ]),
    allowAttributes: set(['alt', 'class', 'height', 'href', 'id', 'name', 'src', 'title', 'width']),
    denyAttributes: new Set(),
    denyTags: set(['form', 'embed', 'object', 'iframe', 'input', 'button']),
  };
}

/**
 * A permissive profile matching unsafe `innerHTML` sinks: everything is
 * allowed, including `<form>`, `<embed>` and `<object>`.
 */
export function unsafeInnerHtmlProfile(): SanitizerProfile {
  return {
    allowTags: null,
    allowAttributes: null,
    denyAttributes: new Set(),
    denyTags: new Set(),
  };
}

/**
 * A sanitizer that strips `id`/`name` only from the tags that matter for
 * named access, while leaving formatting intact. This mirrors the common
 * "remove javascript: and script tags" class of filters that miss clobbering.
 */
export function naiveFilterProfile(): SanitizerProfile {
  return {
    allowTags: null,
    allowAttributes: null,
    // A filter that only knows about script-ish tags.
    denyAttributes: new Set(),
    denyTags: set(['script', 'style', 'link', 'meta', 'base']),
  };
}

export const PROFILES = {
  strictNoIdName: strictNoIdNameProfile,
  richText: richTextProfile,
  unsafeInnerHtml: unsafeInnerHtmlProfile,
  naiveFilter: naiveFilterProfile,
} as const;

export const NAMED_ACCESS_TAGS_SET = set(NAMED_ACCESS_TAGS);
export const NAMED_ACCESS_ATTRS_SET = set(NAMED_ACCESS_ATTRS);
