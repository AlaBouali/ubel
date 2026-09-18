// A small, dependency-free HTML tag parser. It is NOT a spec-compliant HTML
// parser - it covers exactly the subset the original scanners used
// BeautifulSoup for: walking tags by name, filtering by one or two
// attributes, and reading text/attribute content. That keeps this stdlib-only.

const VOID_TAGS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img", "input",
  "link", "meta", "param", "source", "track", "wbr",
]);
const RAW_TEXT_TAGS = new Set(["script", "style"]);

class Node {
  constructor(tagName, attrs = {}) {
    this.tagName = tagName ? tagName.toLowerCase() : null;
    this.attrs = attrs;
    /** @type {(Node|string)[]} */
    this.children = [];
  }

  get contents() {
    return this.children;
  }

  /** requests-style .get(attr, default) */
  get(attr, fallback = "") {
    const v = this.attrs[attr.toLowerCase()];
    return v === undefined ? fallback : v;
  }

  /** Concatenated, recursive text content (mirrors bs4's `.text` / `.get_text()`) */
  get text() {
    let out = "";
    for (const child of this.children) {
      out += typeof child === "string" ? child : child.text;
    }
    return out;
  }

  getText() {
    return this.text;
  }

  _matches(tag, attrs) {
    if (tag && this.tagName !== tag.toLowerCase()) return false;
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (this.get(k, undefined) !== v && !(v === true && this.attrs[k.toLowerCase()] !== undefined)) {
          return false;
        }
      }
    }
    return true;
  }

  /** First matching descendant, or null. `attrs` is an optional {attrName: value} filter. */
  find(tag = null, attrs = null) {
    for (const child of this.children) {
      if (typeof child === "string") continue;
      if (child._matches(tag, attrs)) return child;
      const found = child.find(tag, attrs);
      if (found) return found;
    }
    return null;
  }

  /** All matching descendants. */
  findAll(tag = null, attrs = null) {
    const out = [];
    for (const child of this.children) {
      if (typeof child === "string") continue;
      if (child._matches(tag, attrs)) out.push(child);
      out.push(...child.findAll(tag, attrs));
    }
    return out;
  }
}

function decodeEntities(str) {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ");
}

function parseAttrs(attrString) {
  const attrs = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*("([^"]*)"|'([^']*)'|[^\s"'=<>`]+))?/g;
  let m;
  while ((m = re.exec(attrString))) {
    const name = m[1].toLowerCase();
    const value = m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : m[2] !== undefined ? m[2] : true;
    attrs[name] = value === true ? true : decodeEntities(String(value));
  }
  return attrs;
}

/**
 * Parse an HTML string into a lightweight tree.
 * @param {string} html
 * @returns {Node} a synthetic root node (tagName === null) you can call .find()/.findAll() on
 */
export function parseHTML(html) {
  const root = new Node(null);
  const stack = [root];
  const tagRe = /<!--[\s\S]*?-->|<!DOCTYPE[^>]*>|<\/?([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>/gi;

  let lastIndex = 0;
  let match;
  while ((match = tagRe.exec(html))) {
    const [full, tagName, attrString = "", selfClosingSlash] = match;

    // text between the previous tag and this one
    if (match.index > lastIndex) {
      const text = decodeEntities(html.slice(lastIndex, match.index));
      if (text) stack[stack.length - 1].children.push(text);
    }
    lastIndex = tagRe.lastIndex;

    if (full.startsWith("<!--") || full.toUpperCase().startsWith("<!DOCTYPE")) continue;

    const isClosing = full.startsWith("</");
    if (isClosing) {
      // pop back to the matching open tag, if any
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].tagName === tagName.toLowerCase()) {
          stack.length = i;
          break;
        }
      }
      continue;
    }

    const node = new Node(tagName, parseAttrs(attrString));
    stack[stack.length - 1].children.push(node);

    if (RAW_TEXT_TAGS.has(node.tagName)) {
      const closeRe = new RegExp(`</${node.tagName}\\s*>`, "i");
      const rest = html.slice(lastIndex);
      const closeMatch = closeRe.exec(rest);
      const rawEnd = closeMatch ? closeMatch.index : rest.length;
      node.children.push(rest.slice(0, rawEnd));
      lastIndex += rawEnd + (closeMatch ? closeMatch[0].length : 0);
      tagRe.lastIndex = lastIndex;
      continue;
    }

    if (!selfClosingSlash && !VOID_TAGS.has(node.tagName)) {
      stack.push(node);
    }
  }
  if (lastIndex < html.length) {
    const text = decodeEntities(html.slice(lastIndex));
    if (text) stack[stack.length - 1].children.push(text);
  }
  return root;
}

export { Node };
