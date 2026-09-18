// Port of cpe_parser.py (CPE_Parser), given verbatim by the user.
//
// Two changes from the Python original, both intentional:
//  - xmltodict is replaced by parseSimpleXml(), a small stdlib-only XML reader
//    (good enough for the flat NVD "cpe-list" dictionary format; not a general
//    XML implementation).
//  - `collection` is duck-typed instead of a pymongo Collection: any object
//    exposing `find({...}) -> iterable` and `insertOne(doc)` works, so callers
//    can back it with Mongo, a flat file, or nothing at all.

import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

const CPE_FIELD_ORDER = [
  "type", "vendor", "product", "version", "update", "edition",
  "language", "sw_edition", "target_sw", "target_hw", "other",
];
const KEYWORD_FIELDS = [
  "type", "vendor", "product", "update", "edition",
  "language", "sw_edition", "target_sw", "target_hw", "other",
];

function titleCase(s) {
  return s.replace(/\w\S*/g, (t) => t.charAt(0).toUpperCase() + t.slice(1).toLowerCase());
}

export class CpeParser {
  static getProductName(config, includeVersion = true) {
    const hasBoth = "product" in config && "vendor" in config && config.product !== config.vendor;
    if (hasBoth) {
      if (includeVersion && config.version && config.version !== "*") {
        return `${titleCase(config.vendor)} : ${titleCase(config.product)} / ${config.version}`;
      }
      return `${titleCase(config.vendor)} : ${titleCase(config.product)}`;
    }
    if (includeVersion && config.version && !["*", ""].includes(config.version)) {
      return `${titleCase(config.product)} / ${config.version}`;
    }
    return `${titleCase(config.product)}`;
  }

  static productExistsInList(productDict, productsList) {
    for (const product of productsList) {
      const sameCore =
        productDict.vendor === product.vendor &&
        productDict.product === product.product &&
        productDict.version === product.version;
      if (!sameCore) continue;
      if ("source" in productDict) {
        if (productDict.source === product.source) return true;
      } else {
        return true;
      }
    }
    return false;
  }

  /** Parse a `cpe:/...` (2.2) or `cpe:2.3:...` string into its component fields. */
  static parseCpe(cpeString) {
    if (!cpeString) return undefined;
    let parts;
    if (cpeString.startsWith("cpe:/")) {
      parts = ["", ...cpeString.split("cpe:/")[1].split(":")];
    } else {
      parts = cpeString.split("cpe:2.3")[1].split(":");
    }
    let productType;
    if (parts[1] === "o") productType = "operating system";
    else if (parts[1] === "h") productType = "hardware";
    else productType = "application";

    const info = { type: productType, vendor: parts[2], product: parts[3] };
    if (parts.length > 4) info.version = parts[4];
    if (parts.length > 5) info.update = parts[5];
    if (parts.length > 6) info.edition = parts[6];
    if (parts.length > 7) info.language = parts[7];
    if (parts.length > 8) info.sw_edition = parts[8];
    if (parts.length > 9) info.target_sw = parts[9];
    if (parts.length > 10) info.target_hw = parts[10];
    if (parts.length > 11) info.other = parts[11];
    return info;
  }

  static assembleCpe(cpeDict, ignoreVersion = true) {
    const dict = { ...cpeDict };
    if (ignoreVersion) dict.version = "*";
    return CPE_FIELD_ORDER.filter((f) => f in dict)
      .map((f) => dict[f])
      .join(":");
  }

  static getKeywordsFromParsedCpe(parsedCpe) {
    const out = new Set();
    for (const field of KEYWORD_FIELDS) {
      const value = parsedCpe[field];
      if (value === undefined || value === null || value === "" || value === "*" || value === "-") continue;
      out.add(value);
      out.add(value.replace(/-/g, "_").replace(/ /g, "_"));
      const cleaned = value.replace(/@/g, "").replace(/\\/g, "").replace(/\//g, "_").replace(/-/g, "_").replace(/\./g, "_");
      for (const piece of cleaned.split("_")) {
        const p = piece.replace(/@/g, "").replace(/\\/g, "");
        if (p.trim() !== "") out.add(p);
      }
    }
    return [...out].filter((x) => x.trim() !== "");
  }

  static getInfosFromParsedCpe(parsedCpe) {
    const out = [];
    for (const field of KEYWORD_FIELDS) {
      const value = parsedCpe[field];
      if (value === undefined || value === null || value === "" || value === "*" || value === "-") continue;
      out.push(value);
    }
    return out.filter((x) => x.trim() !== "");
  }

  /**
   * Load an NVD-style CPE dictionary (JSON or XML) and upsert each entry into `collection`.
   * @param {string} fileName
   * @param {{find: (q: object) => Iterable<any>, insertOne: (doc: object) => void}} collection
   */
  static parseCpesFromJson(fileName, collection) {
    let cpes;
    if (fileName.endsWith(".json")) {
      cpes = JSON.parse(readFileSync(fileName, "utf-8"))["cpe-list"]["cpe-item"];
    } else {
      const xml = readFileSync(fileName, "utf-8");
      cpes = parseSimpleXml(xml)["cpe-list"]["cpe-item"];
    }
    const items = Array.isArray(cpes) ? cpes : [cpes];

    for (const x of items) {
      const name = x["cpe-23:cpe23-item"]["@name"].replace(/\\/g, "");
      const parsedCpe = CpeParser.parseCpe(name);
      const keywords = CpeParser.getKeywordsFromParsedCpe(parsedCpe);
      const infos = CpeParser.getInfosFromParsedCpe(parsedCpe);
      parsedCpe.version = "*";

      const existing = [...collection.find({ infos })];
      if (existing.length !== 0) continue;

      parsedCpe.hash_id = createHash("sha256").update(randomUUID() + String(keywords)).digest("hex");
      parsedCpe.keywords = keywords;
      parsedCpe.infos = infos;

      const titles = [];
      const rawTitles = Array.isArray(x.title) ? x.title : [x.title];
      for (const t of rawTitles) {
        titles.push({ language: t["@xml:lang"], text: String(t["#text"]).replace(parsedCpe.version, "") });
      }

      const references = [];
      try {
        const rawRefs = x.references?.reference;
        const refList = Array.isArray(rawRefs) ? rawRefs : [rawRefs];
        for (const r of refList) {
          if (r) references.push({ url: r["@href"], text: r["#text"] });
        }
      } catch {
        // no references block for this item
      }

      parsedCpe.title = titles;
      parsedCpe.references = references;
      collection.insertOne(parsedCpe);
    }
  }
}

/**
 * Minimal recursive-descent XML reader tailored to the flat NVD CPE dictionary
 * shape: element attributes become "@attr" keys, text content becomes "#text",
 * and repeated child tags become arrays. Not a general-purpose XML parser.
 */
export function parseSimpleXml(xml) {
  let i = 0;
  xml = xml.replace(/<\?xml[\s\S]*?\?>/, "").replace(/<!--[\s\S]*?-->/g, "");

  function skipWs() {
    while (i < xml.length && /\s/.test(xml[i])) i++;
  }

  function parseAttrs(str) {
    const attrs = {};
    const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
    let m;
    while ((m = re.exec(str))) attrs[m[1]] = m[3] !== undefined ? m[3] : m[4];
    return attrs;
  }

  function parseElement() {
    skipWs();
    if (xml[i] !== "<") return null;
    const tagMatch = /^<([a-zA-Z_][-a-zA-Z0-9_:.]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>/.exec(xml.slice(i));
    if (!tagMatch) return null;
    const [full, tagName, attrString, selfClose] = tagMatch;
    i += full.length;

    const node = { name: tagName, ...parseAttrsPrefixed(attrString) };
    if (selfClose) return node;

    const children = {};
    let text = "";
    while (i < xml.length) {
      skipWs();
      if (xml.slice(i, i + 2 + tagName.length + 1) === `</${tagName}>`) {
        i += tagName.length + 3;
        break;
      }
      if (xml[i] === "<") {
        const child = parseElement();
        if (!child) break;
        const { name, ...rest } = child;
        if (children[name] === undefined) children[name] = rest;
        else if (Array.isArray(children[name])) children[name].push(rest);
        else children[name] = [children[name], rest];
      } else {
        const start = i;
        while (i < xml.length && xml[i] !== "<") i++;
        text += xml.slice(start, i);
      }
    }
    const trimmed = text.trim();
    if (trimmed) node["#text"] = decodeXmlEntities(trimmed);
    Object.assign(node, children);
    return node;
  }

  function parseAttrsPrefixed(attrString) {
    const raw = parseAttrs(attrString);
    const out = {};
    for (const [k, v] of Object.entries(raw)) out["@" + k] = decodeXmlEntities(v);
    return out;
  }

  skipWs();
  const root = parseElement();
  const { name, ...rest } = root;
  return { [name]: rest };
}

function decodeXmlEntities(str) {
  return str
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}
