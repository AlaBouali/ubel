// Port of cms/wp.py - fingerprinting portions only.
//
// The original file mixes CMS fingerprinting with a large amount of code that
// is NOT fingerprinting: a CVE/vulnerability lookup class (WP_Vulnerability_Search,
// which queries wpvulnerability.net / wordfence.com / patchstack.com / wpscan.com /
// cve.mitre.org), XML-RPC brute-force and pingback-SSRF helpers, an admin
// login-bruteforce helper, and REST/author-archive user-enumeration helpers,
// plus a `scan_dast` misconfiguration scan built on top of those (and which the
// original's own `scan()` never calls - the call site is commented out).
//
// None of that is fingerprinting a product/version, so none of it is ported.
// What's here is exactly the detection logic: WordPress core version, theme
// and plugin identification from page markup, and the informational
// (read-only, no credentials, no exploitation) XML-RPC method listing.

import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

/** Generic `<meta name="generator" content="...">` version reader (second word of the content attribute). */
export async function getVersion(u, opts = {}) {
  const hed = buildHeaders(opts);
  try {
    const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 15 });
    return between(res.text, '<meta name="generator" content="', '"').trim().split(" ")[1];
  } catch {
    return undefined;
  }
}

/** Lists the XML-RPC methods xmlrpc.php exposes - read-only introspection, no bruteforce/exploit attempt. */
export async function getXmlrpcMethods(u, opts = {}) {
  u = stripTrailingSlash(u) + (opts.path || "/xmlrpc.php");
  const hed = buildHeaders(opts);
  const post = `
<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
`;
  try {
    const res = await httpClient.post(u, post, { headers: hed, timeout: opts.timeout ?? 10 });
    return res.text
      .split("<data>")[1]
      .split("</data>")[0]
      .trim()
      .split("\n")
      .map((x) => x.replace("</string></value>", "").replace("<value><string>", "").trim());
  } catch {
    return [];
  }
}

function extractHrefVersion(href) {
  try {
    const version = href.split("?")[1].split("=")[1];
    if (version.length > 10 && !version.includes(".")) return "";
    return version;
  } catch {
    return "";
  }
}

export const WordPressScanner = registerScanner({
  application: "wordpress",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 20;

    let response;
    try {
      response = await httpClient.get(u, { headers: hed, timeout });
    } catch {
      return { application: {}, components: [] };
    }
    const text = response.text;
    const soup = parseHTML(text);

    let wpVersion = "";
    try {
      wpVersion = between(text, '<meta name="generator" content="WordPress', '"').trim();
    } catch {
      wpVersion = "";
    }

    const themes = [];
    const plugins = [];
    for (const link of soup.findAll("link", { rel: "stylesheet" })) {
      const href = link.get("href");
      if (!href) continue;
      if (href.includes("themes") && href.includes(".css")) {
        try {
          const themeName = href.split("/themes/")[1].split("/")[0];
          const theme = { name: themeName, version: extractHrefVersion(href) };
          if (!themes.some((t) => t.name === theme.name && t.version === theme.version)) themes.push(theme);
        } catch {
          // href didn't match the expected /themes/<name>/ shape
        }
      } else if (href.includes("plugins") && href.includes(".css")) {
        try {
          const pluginName = href.split("/plugins/")[1].split("/")[0];
          const plugin = { name: pluginName, version: extractHrefVersion(href) };
          if (!plugins.some((p) => p.name === plugin.name && p.version === plugin.version)) plugins.push(plugin);
        } catch {
          // href didn't match the expected /plugins/<name>/ shape
        }
      }
    }

    if (text.includes('<meta name="generator" content="Site Kit by Google')) {
      plugins.push({ name: "SiteKit", version: between(text, '<meta name="generator" content="Site Kit by Google', '"').trim() });
    }
    if (text.includes('<meta name="generator" content="Elementor ')) {
      if (!plugins.some((p) => p.name === "revslider")) {
        plugins.push({ name: "elementor", version: between(text, '<meta name="generator" content="Elementor ', ";").trim() });
      }
    }
    if (text.includes('<meta name="generator" content="Powered by Slider Revolution ')) {
      if (!plugins.some((p) => p.name === "revslider")) {
        plugins.push({
          name: "revslider",
          version: between(text, '<meta name="generator" content="Powered by Slider Revolution ', "-").trim(),
        });
      }
    }
    if (text.includes('<meta name="generator" content="Powered by WPBakery Page Builder ')) {
      plugins.push({
        name: "js_composer",
        version: between(text, '<meta name="generator" content="Powered by WPBakery Page Builder ', "-").trim(),
      });
    }
    if (text.includes('<meta name="generator" content="WooCommerce ')) {
      plugins.push({ name: "woocommerce", version: between(text, '<meta name="generator" content="WooCommerce ', '"').trim() });
    }
    if (text.includes('<meta name="framework" content="Redux')) {
      plugins.push({ name: "redux-framework", version: between(text, '<meta name="framework" content="Redux', '"').trim() });
    }
    if (text.includes("var RocketPreloadLinksConfig")) {
      try {
        const r = await httpClient.get(u + "/robots.txt", { headers: hed, timeout });
        if (r.headers.get("X-Powered-By", "").includes("WP Rocket")) {
          plugins.push({ name: "wp-rocket", version: r.headers.get("X-Powered-By", "").split("WP Rocket/")[1].split(/\s+/)[0] });
        }
      } catch {
        // robots.txt unreachable - skip the WP Rocket header check
      }
    }

    let phpVersion = "";
    try {
      phpVersion = response.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1] || "";
    } catch {
      phpVersion = "";
    }
    if (phpVersion === "") phpVersion = await fetchPhpVersionFallback(u, hed, timeout);

    const components = [{ product: "php", vendor: "php", version: phpVersion }];
    for (const theme of themes) {
      components.push({ product: theme.name, version: theme.version, tags: ["wordpress theme"] });
    }
    for (const plugin of plugins) {
      components.push({ product: plugin.name, version: plugin.version, tags: ["wordpress plugin"] });
    }

    return { application: { product: "wordpress", vendor: "wordpress", version: wpVersion }, components };
  },
  isValid: ({ data }) => ['<meta name="generator" content="WordPress', "/wp-content/"].some((x) => data.includes(x)),
});
