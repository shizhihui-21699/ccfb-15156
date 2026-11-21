/**
 * Lightweight taint propagation.
 *
 * Real (and bundled) code almost never uses a clobberable global directly in a
 * dangerous position:
 *
 *     var c = window.CONFIG || {};
 *     var u = c.cdn;
 *     s.src = u;
 *
 * The read that matters (`window.CONFIG`) is three assignments away from the
 * sink. This pass connects them: it propagates "derived from a clobberable
 * global" through local variables (assignments, declarations, simple aliases,
 * member reads, and destructuring), then marks the originating reads whose
 * taint reaches a URL/call sink.
 *
 * The pass is intra-procedural and flow-insensitive. That over-approximates
 * (a variable assigned in one branch taints readers in another), which is the
 * safe direction for a detector: it can report a *possible* flow that a human
 * then confirms. It never invents a flow that does not exist in the AST.
 */

import * as walk from 'acorn-walk';
import type * as estree from 'estree';
import type { GlobalRead, UsageKind } from './globals.ts';
import { DOCUMENT_ALIASES, WINDOW_ALIASES } from './globals.ts';
import type { ParsedScript } from './parse.ts';
import type * as eslintScope from 'eslint-scope';
import { isEnvironmentGlobal as envGlobal } from './environment.ts';

/** A reference to a clobberable global: window-scoped name or document member. */
interface GlobalRef {
  name: string;
  scope: 'window' | 'document';
}

/** Unique key for a (scope, name) pair. */
function refKey(r: GlobalRef): string {
  return `${r.scope}\u0000${r.name}`;
}

const URL_SINK_PROPS = new Set([
  'src',
  'href',
  'action',
  'formAction',
  'data',
  'poster',
  'srcset',
  'ping',
]);
const URL_SINK_CALLEES = new Set([
  'fetch',
  'importScripts',
  'open',
  'assign',
  'replace',
  'navigate',
]);

/**
 * Extract every clobberable global referenced inside an expression, following
 * known local aliases as it goes. This is the taint source set for a value.
 */
type AliasMap = Map<eslintScope.Variable, Set<string>>;

function collectRefs(
  node: estree.Node | null | undefined,
  ctx: TaintContext,
  out: Set<string>,
  seenAliases: Set<eslintScope.Variable> = new Set(),
): void {
  if (!node) return;
  if (node.type === 'MemberExpression') {
    const root = rootOfMember(node);
    if (root) {
      if (root.type === 'Identifier' && WINDOW_ALIASES.has(root.name) && !ctx.isLocal(root)) {
        const prop = staticPropertyName(node);
        if (prop) out.add(refKey({ name: prop, scope: 'window' }));
      } else if (root.type === 'Identifier' && DOCUMENT_ALIASES.has(root.name) && !ctx.isLocal(root)) {
        const prop = staticPropertyName(node);
        if (prop) out.add(refKey({ name: prop, scope: 'document' }));
      } else if (root.type === 'Identifier') {
        const v = ctx.variableOf(root);
        if (v) {
          const alias = ctx.aliases.get(v);
          if (alias && !seenAliases.has(v)) {
            seenAliases.add(v);
            for (const k of alias) out.add(k);
          }
        }
      } else if (root.type === 'ThisExpression') {
        // this.CONFIG at top level is a global read; include it conservatively.
        const prop = staticPropertyName(node);
        if (prop) out.add(refKey({ name: prop, scope: 'window' }));
      }
    }
  } else if (node.type === 'Identifier') {
    const v = ctx.variableOf(node);
    if (v) {
      const alias = ctx.aliases.get(v);
      if (alias && !seenAliases.has(v)) {
        seenAliases.add(v);
        for (const k of alias) out.add(k);
      }
    }
  }
  // Recurse into children (generic visitor).
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'range' || key === 'start' || key === 'end' || key === 'type') continue;
    const child = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const c of child) if (isNode(c)) collectRefs(c, ctx, out, seenAliases);
    } else if (isNode(child)) {
      collectRefs(child, ctx, out, seenAliases);
    }
  }
}

/**
 * Resolution context for taint: maps identifier nodes to their resolved scope
 * variable, so two different `var t` in different functions never share taint.
 */
interface TaintContext {
  aliases: AliasMap;
  variableOf(node: estree.Node): eslintScope.Variable | null;
  /** True when the identifier resolves to a non-global binding. */
  isLocal(node: estree.Node): boolean;
}

function isNode(v: unknown): v is estree.Node {
  return typeof v === 'object' && v !== null && typeof (v as { type?: unknown }).type === 'string';
}

function rootOfMember(node: estree.MemberExpression): estree.Node {
  let cur: estree.Node = node;
  while (cur.type === 'MemberExpression') cur = cur.object;
  return cur;
}

function staticPropertyName(node: estree.MemberExpression): string | null {
  if (!node.computed && node.property.type === 'Identifier') return node.property.name;
  if (node.computed && node.property.type === 'Literal' && node.property.value != null) {
    return String(node.property.value);
  }
  return null;
}

/** All names declared anywhere in the script (any scope). */
function collectDeclaredNames(parsed: ParsedScript): Set<string> {
  const names = new Set<string>();
  for (const scope of parsed.scopeManager.scopes) {
    for (const v of scope.variables) names.add(v.name);
  }
  return names;
}

/** Is this member-expression access reading a URL-bearing property? */
function memberIsUrlProperty(
  node: estree.MemberExpression,
  isLocal: (n: estree.Node) => boolean = () => false,
): boolean {
  const prop = staticPropertyName(node);
  if (prop == null) return false;
  if (URL_SINK_PROPS.has(prop)) return true;
  // `window.location` / `document.location` assignment navigates.
  if (prop === 'location') {
    const root = rootOfMember(node);
    if (root.type === 'Identifier' && !isLocal(root)) {
      return WINDOW_ALIASES.has(root.name) || DOCUMENT_ALIASES.has(root.name);
    }
  }
  return false;
}

export interface TaintResult {
  /** Extra usages to merge into each read, keyed by scope+name. */
  usagesByRef: Map<string, Set<UsageKind>>;
  /** Number of alias iterations performed (diagnostics). */
  iterations: number;
}

/**
 * Run the taint pass over one parsed script.
 */
export function propagateTaint(parsed: ParsedScript): TaintResult {
  // Map identifier nodes to the scope variable they resolve to. eslint-scope
  // gives us real variable objects, so two distinct `var t` in different
  // functions are different keys and never share taint.
  const varOf = new Map<estree.Node, eslintScope.Variable>();
  const globalScope = parsed.scopeManager.globalScope;
  for (const scope of parsed.scopeManager.scopes) {
    for (const ref of scope.references) {
      if (ref.resolved) varOf.set(ref.identifier as unknown as estree.Node, ref.resolved);
    }
    for (const v of scope.variables) {
      for (const id of v.identifiers) varOf.set(id as unknown as estree.Node, v);
    }
  }
  const variableOf = (node: estree.Node): eslintScope.Variable | null => varOf.get(node) ?? null;
  const isLocal = (node: estree.Node): boolean => {
    const v = varOf.get(node);
    return !!v && v.scope !== globalScope;
  };

  const ctx: TaintContext = { aliases: new Map(), variableOf, isLocal };

  // Seed aliases from declarations and assignments to a resolved variable.
  const seeders: Array<{ variable: eslintScope.Variable; node: estree.Node | null }> = [];
  const addSeeder = (id: estree.Node, value: estree.Node | null) => {
    if (id.type !== 'Identifier') return;
    const v = varOf.get(id);
    if (v) seeders.push({ variable: v, node: value });
  };
  walk.simple(parsed.ast, {
    VariableDeclarator(node: estree.VariableDeclarator) {
      if (node.id.type === 'Identifier') addSeeder(node.id, node.init ?? null);
    },
    AssignmentExpression(node: estree.AssignmentExpression) {
      if (node.left.type === 'Identifier') addSeeder(node.left, node.right ?? null);
    },
  } as never);

  // Destructuring seeds: `const { CONFIG } = window` and
  // `const { cdn } = window.CONFIG` both taint the bound locals.
  walk.simple(parsed.ast, {
    VariableDeclarator(node: estree.VariableDeclarator) {
      if (node.id.type !== 'ObjectPattern' || !node.init) return;
      const init = node.init;
      const fromGlobalObject =
        init.type === 'Identifier' && !isLocal(init) && (WINDOW_ALIASES.has(init.name) || DOCUMENT_ALIASES.has(init.name));
      const scope: 'window' | 'document' =
        init.type === 'Identifier' && DOCUMENT_ALIASES.has(init.name) ? 'document' : 'window';

      for (const p of node.id.properties) {
        if (p.type !== 'Property' || p.computed) continue;
        let key: string | null = null;
        if (p.key.type === 'Identifier') key = p.key.name;
        else if (p.key.type === 'Literal' && p.key.value != null) key = String(p.key.value);
        if (!key) continue;
        if (p.value.type !== 'Identifier') continue;
        const v = varOf.get(p.value);
        if (!v) continue;
        const set = ctx.aliases.get(v) ?? new Set<string>();
        if (fromGlobalObject) {
          // `const { X } = window` — X names a window property.
          set.add(refKey({ name: key, scope }));
        } else {
          // `const { cdn } = window.CONFIG` — inherits CONFIG's taint.
          const src = new Set<string>();
          collectRefs(init, ctx, src);
          for (const k of src) set.add(k);
        }
        ctx.aliases.set(v, set);
      }
    },
  } as never);

  // Free globals: identifiers that resolve to nothing in this script are window
  // properties an element could supply. Seed a taint source keyed by a synthetic
  // variable so they flow through aliases like any binding.
  const freeGlobalVars = new Map<string, eslintScope.Variable>();
  walk.simple(parsed.ast, {
    Identifier(node: estree.Identifier) {
      if (WINDOW_ALIASES.has(node.name) || DOCUMENT_ALIASES.has(node.name)) return;
      if (varOf.has(node as unknown as estree.Node)) return;
      if (envGlobal(node.name)) return;
      // Create (or reuse) a synthetic variable for this free name.
      let v = freeGlobalVars.get(node.name);
      if (!v) {
        v = { name: node.name } as unknown as eslintScope.Variable;
        freeGlobalVars.set(node.name, v);
        ctx.aliases.set(v, new Set([refKey({ name: node.name, scope: 'window' })]));
      }
      varOf.set(node as unknown as estree.Node, v);
    },
  } as never);

  let iterations = 0;
  for (let changed = true; changed && iterations < 12; ) {
    changed = false;
    iterations++;
    for (const { variable, node } of seeders) {
      const refs = new Set<string>();
      collectRefs(node, ctx, refs);
      if (refs.size === 0) continue;
      const cur = ctx.aliases.get(variable) ?? new Set<string>();
      const before = cur.size;
      for (const r of refs) cur.add(r);
      if (cur.size !== before) {
        ctx.aliases.set(variable, cur);
        changed = true;
      }
    }
  }

  const usagesByRef = new Map<string, Set<UsageKind>>();
  const addUsage = (key: string, u: UsageKind) => {
    const s = usagesByRef.get(key) ?? new Set<UsageKind>();
    s.add(u);
    usagesByRef.set(key, s);
  };

  walk.simple(parsed.ast, {
    AssignmentExpression(node: estree.AssignmentExpression) {
      const isNavigation =
        (node.left.type === 'Identifier' && node.left.name === 'location' && !isLocal(node.left)) ||
        (node.left.type === 'MemberExpression' && memberIsUrlProperty(node.left, isLocal));
      if (!isNavigation) return;
      const refs = new Set<string>();
      collectRefs(node.right, ctx, refs);
      for (const r of refs) addUsage(r, 'url-sink');
    },
    CallExpression(node: estree.CallExpression) {
      const callee = node.callee;
      let isSink = false;
      if (callee.type === 'Identifier' && URL_SINK_CALLEES.has(callee.name) && !isLocal(callee)) isSink = true;
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.property.type === 'Identifier' &&
        URL_SINK_CALLEES.has(callee.property.name)
      ) {
        isSink = true;
      }
      if (!isSink) return;
      for (const arg of node.arguments) {
        const refs = new Set<string>();
        collectRefs(arg.type === 'SpreadElement' ? arg.argument : arg, ctx, refs);
        for (const r of refs) addUsage(r, 'url-sink');
      }
    },
    TemplateLiteral(node: estree.TemplateLiteral) {
      for (const expr of node.expressions) {
        const refs = new Set<string>();
        collectRefs(expr, ctx, refs);
        for (const r of refs) addUsage(r, 'string-coerce');
      }
    },
  } as never);

  return { usagesByRef, iterations };
}

/**
 * Merge taint-derived usages into extracted reads. A read gains a usage when
 * any script's taint analysis attributed that usage to its (scope, name).
 */
export function applyTaint(
  reads: readonly GlobalRead[],
  taintByScript: ReadonlyMap<string, TaintResult>,
): GlobalRead[] {
  return reads.map((read) => {
    const taint = taintByScript.get(read.scriptId);
    if (!taint) return read;
    const scope = read.scope;
    const key = refKey({ name: read.name, scope });
    const extra = taint.usagesByRef.get(key);
    if (!extra || extra.size === 0) return read;
    const usages = new Set<UsageKind>(read.usages);
    for (const u of extra) usages.add(u);
    return { ...read, usages: [...usages] };
  });
}
