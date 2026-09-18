// Port of bane.gather_info.backends.Backend_Fingerprinter (backends.py, given verbatim).

const SERVER_TOKEN_MAP = {
  glassfish: { product: "glassfish_server", vendor: "oracle" }, // version handled specially (last token)
  undertow: { product: "undertow", vendor: "redhat" },
  uvicorn: { product: "uvicorn", vendor: "encode" },
  prtg: { product: "prtg_network_monitor", vendor: "paessler" },
  srs: { product: "simple_realtime_server", vendor: "ossrs" },
  beegoserver: { product: "beego", vendor: "beego" },
  abyss: { product: "abyss_web_server", vendor: "aprelium_technologies" },
  "goahead-webs": { product: "goahead_webserver", vendor: "goahead" },
  "peersec-matrixssl": { product: "matrixssl", vendor: "peersec_networks" },
  express: { product: "express", vendor: "openjsf" },
  nodejs: { product: "nodejs", vendor: "nodejs" },
  "node.js": { product: "node.js", vendor: "nodejs" },
  splunkd: { product: "splunk", vendor: "splunk" },
  webrick: { product: "webrick", vendor: "ruby-lang" },
  nexus: { product: "nexus", vendor: "sonatype" },
  miniupnpd: { product: "miniupnpd", vendor: "miniupnp.free" },
  mini_httpd: { product: "mini_httpd", vendor: "acme" },
  thttpd: { product: "thttpd", vendor: "acme" },
  payara: { product: "payara", vendor: "payara" }, // version handled specially (token[2])
  apache: { product: "http_server", vendor: "apache" },
  nginx: { product: "nginx", vendor: "f5" },
  "microsoft-iis": { product: "internet_information_services", vendor: "microsoft" },
  litespeed: { product: "litespeed_web_server", vendor: "litespeedtech" },
  openresty: { product: "openresty", vendor: "openresty" },
  caddy: { product: "caddy", vendor: "caddyserver" },
  cherokee: { product: "cherokee", vendor: "cherokee-project" },
  "apache-coyote": { product: "tomcat", vendor: "apache" },
  ibm_http_server: { product: "http_server", vendor: "ibm" },
  gunicorn: { product: "gunicorn", vendor: "gunicorn" },
  tengine: { product: "tengine", vendor: "alibaba" },
  uwsgi: { product: "unbit", vendor: "uwsgi" },
  jetty: { product: "jetty_http_server", vendor: "jetty" },
  lighttpd: { product: "lighttpd", vendor: "lighttpd" },
  resin: { product: "resin", vendor: "caucho_technology" },
  cowboy: { product: "http_server", vendor: "ninenines" },
  tornadoserver: { product: "tornado", vendor: "tornadoweb" },
  zeus: { product: "zeus_web_server", vendor: "zeus_technologies" },
  "sun-one-web-server": { product: "one_application_server", vendor: "sun" },
  raven: { product: "raven", vendor: "raven_software" },
  aolserver: { product: "aol_server", vendor: "aol" },
  yaws: { product: "yaws", vendor: "yaws" },
  rackspace: { product: "openstack_windows_guest_agent", vendor: "rackspace" },
  cern: { product: "cern_httpd", vendor: "w3c" },
  squid: { product: "squid", vendor: "squid-cache" },
  cherrypy: { product: "cherrypy", vendor: "cherrypy" },
  openssl: { product: "openssl", vendor: "openssl" },
  mod_wsgi: { product: "mod_wsgi", vendor: "modwsgi" },
  python: { product: "python", vendor: "python" },
  werkzeug: { product: "werkzeug", vendor: "palletsprojects" },
};
// tokens whose version comes from server.split()[counter+1] instead of "product/version"
const NEXT_TOKEN_VERSION = new Set(["hiawatha", "mongrel", "puma", "mod_ssl"]);

function versionFromToken(token) {
  const parts = token.split("/");
  return parts.length > 1 ? parts[1] : "";
}

export class BackendFingerprinter {
  /**
   * @param {import("./httpClient.js").Headers} headers
   */
  static analyze(headers) {
    const server = headers.get("Server", "");
    const serverInfo = [];

    if (server.includes("Upstash Kafka Server")) {
      let upstashVersion = "";
      try {
        upstashVersion = server.split("(")[1].split(" ")[0];
      } catch {
        upstashVersion = "";
      }
      serverInfo.push({ product: "kafka_server", vendor: "upstash", version: upstashVersion });
    }
    if (headers.get("X-Powered-By", "").toLowerCase().includes("express")) {
      const xpb = headers.get("X-Powered-By", "");
      const parts = xpb.split("/");
      if (parts.length <= 1) {
        serverInfo.push({ product: "express", vendor: "openjsf", version: "" });
      }
      // NB: the original also silently drops the version-bearing case (its own bug, preserved)
    }
    if (headers.get("X-Powered-By", "") === "Strapi <strapi.io>") {
      serverInfo.push({ product: "strapi", vendor: "strapi", version: "" });
    }

    const serverTokens = server.split(/\s+/).filter(Boolean);
    for (let i = 0; i < serverTokens.length; i++) {
      const rawToken = serverTokens[i];
      const token = rawToken.replace(")", "");
      const key = token.split("/")[0].toLowerCase();
      const version = versionFromToken(token);

      if (key === "glassfish") {
        serverInfo.push({ product: "glassfish_server", vendor: "oracle", version: serverTokens[serverTokens.length - 1] });
        break;
      } else if (key === "(ruby") {
        serverInfo.push({ product: "ruby", vendor: "ruby-lang", version: version.split("/")[0].split(")")[0] });
      } else if (key === "payara") {
        serverInfo.push({ product: "payara", vendor: "payara", version: serverTokens[2] });
        break;
      } else if (NEXT_TOKEN_VERSION.has(key)) {
        const v = (serverTokens[i + 1] || "").replace(/v/gi, "");
        const meta = SERVER_TOKEN_MAP[key];
        if (meta) serverInfo.push({ product: meta.product, vendor: meta.vendor, version: v });
      } else if (SERVER_TOKEN_MAP[key]) {
        const meta = SERVER_TOKEN_MAP[key];
        serverInfo.push({ product: meta.product, vendor: meta.vendor, version });
      }
    }

    const osMatch = serverTokens.find((t) => t.startsWith("("));
    const serverOs = osMatch ? osMatch.replace("(", "").replace(")", "") : "";

    const backendInfo = [];
    const backend = headers.get("X-Powered-By", "");
    if (backend !== "") {
      const backendTokens = backend.split(/\s+/).filter(Boolean);
      backendTokens.forEach((rawToken, i) => {
        const token = rawToken.replace(")", "");
        const key = token.split("/")[0].toLowerCase();
        const version = versionFromToken(token);
        if (key === "php") {
          backendInfo.push({ product: "php", vendor: "php", version });
        } else if (key === "python") {
          const pyVersion = backendTokens[i + 1] || "";
          serverInfo.push({ product: "python", vendor: "python", version: pyVersion });
        }
      });
      if (backend.includes("Phusion Passenger (")) {
        try {
          const version = backend.split("Phusion Passenger (")[1].split(")")[1];
          serverInfo.push({ product: "passenger", vendor: "phusion", version });
        } catch {
          backendInfo.push({ product: "passenger", vendor: "phusion", version: "" });
        }
      }
    }

    const aspVersion = headers.get("X-AspNet-Version", "");
    if (aspVersion !== "") backendInfo.push({ product: "asp.net", vendor: "microsoft", version: aspVersion });

    const jenkinsVersion = headers.get("X-Jenkins", "");
    if (jenkinsVersion !== "") backendInfo.push({ product: "jenkins", vendor: "jenkins", version: jenkinsVersion });

    for (const x of serverInfo) x.tags = ["web server"];
    for (const x of backendInfo) x.tags = ["backend"];

    return { server: serverInfo, backend: backendInfo, operating_system: serverOs };
  }
}
