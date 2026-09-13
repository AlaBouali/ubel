'use strict';

/**
 * Minimal, dependency-free XML -> plain object parser.
 *
 * Not a general-purpose XML parser (no DTD, no CDATA edge cases, no
 * namespace resolution) — it's built specifically to handle the shape of
 * responses AWS's "query protocol" and REST/XML APIs (S3, EC2, IAM, RDS)
 * return. Those are well-formed, attribute-light, and namespace-prefixed
 * only on the root element, which keeps this tractable.
 *
 * Rules:
 *  - An element with only text content becomes a string.
 *  - An element with child elements becomes an object keyed by tag name
 *    (namespace prefixes, if any, are stripped).
 *  - A tag that repeats under the same parent becomes an array.
 *  - Empty elements (<Foo/> or <Foo></Foo>) become an empty string.
 */

const TOKEN_RE =
  /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[([\s\S]*?)\]\]>|<\/\s*([a-zA-Z_][\w.:-]*)\s*>|<\s*([a-zA-Z_][\w.:-]*)((?:\s+[a-zA-Z_][\w.:-]*\s*=\s*"[^"]*")*)\s*(\/?)\s*>|([^<]+)/g;

const ATTR_RE = /([a-zA-Z_][\w.:-]*)\s*=\s*"([^"]*)"/g;

function decodeEntities(text) {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function stripNs(name) {
  const idx = name.indexOf(':');
  return idx === -1 ? name : name.slice(idx + 1);
}

function addChild(node, name, value) {
  if (Object.prototype.hasOwnProperty.call(node, name)) {
    if (!Array.isArray(node[name])) node[name] = [node[name]];
    node[name].push(value);
  } else {
    node[name] = value;
  }
}

/**
 * Parse an XML string into a plain object tree.
 * Returns { [rootTagName]: parsedValue }.
 */
function parseXML(xml) {
  if (typeof xml !== 'string' || xml.trim() === '') return {};

  // Stack of { name, obj, text } frames. obj accumulates element children;
  // text accumulates raw text seen directly inside this element.
  const stack = [{ name: null, obj: {}, text: '' }];

  let match;
  TOKEN_RE.lastIndex = 0;
  while ((match = TOKEN_RE.exec(xml)) !== null) {
    const [, cdata, closeName, openName, , selfClose, text] = match;

    if (cdata !== undefined) {
      stack[stack.length - 1].text += cdata;
      continue;
    }

    if (closeName !== undefined) {
      const frame = stack.pop();
      const parent = stack[stack.length - 1];
      const tag = stripNs(closeName);
      const hasChildren = Object.keys(frame.obj).length > 0;
      const trimmedText = frame.text.trim();
      const value = hasChildren ? frame.obj : decodeEntities(trimmedText);
      addChild(parent.obj, tag, value);
      continue;
    }

    if (openName !== undefined) {
      const tag = stripNs(openName);
      if (selfClose === '/') {
        addChild(stack[stack.length - 1].obj, tag, '');
      } else {
        stack.push({ name: tag, obj: {}, text: '' });
      }
      continue;
    }

    if (text !== undefined) {
      stack[stack.length - 1].text += text;
    }
  }

  return stack[0].obj;
}

/** Always return an array, whether the parsed value was absent, a single
 * object, or already an array. Convenience for walking repeated elements
 * like <member> or <item> lists without repeating null/array checks. */
function asArray(value) {
  if (value === undefined || value === null || value === '') return [];
  return Array.isArray(value) ? value : [value];
}

export { parseXML, asArray, decodeEntities };
