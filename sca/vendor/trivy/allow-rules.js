/**
 * allow-rules.js — global suppression rules.
 *
 * PORTED, NOT ORIGINAL WORK. Ported from Trivy's built-in secrets scanner
 * allow-list:
 *
 *   https://github.com/aquasecurity/trivy
 *   pkg/fanal/secret/builtin-allow-rules.go
 *   Copyright the Trivy Authors — licensed under the Apache License, Version 2.0
 *
 * See NOTICE and LICENSE in the package root. This file (and this package)
 * is licensed under Apache-2.0, matching the upstream source.
 *
 * Each rule may carry a `path` regex (tested against the file's path,
 * relative to the scan root, forward-slash-separated) and/or a `content`
 * regex (tested against the specific matched secret text). A finding is
 * suppressed if either present regex matches — this mirrors Trivy's
 * "examples" rule, which carries both a path and a content pattern as
 * independent conditions.
 */

export const builtinAllowRules = [
  {
    // `.dist-info` dir contains only metadata files such as version, license, and entry points.
    // cf. https://github.com/aquasecurity/trivy/issues/8212
    id: "dist-info",
    description: "Ignore Python .dist-info metadata directories",
    path: /\.dist-info\//,
  },
  {
    id: "tests",
    description: "Avoid test files and paths",
    path: /(^(?:test)|\/test|-test|_test|\.test)/i,
  },
  {
    id: "examples",
    description: "Avoid example files and paths", // e.g. https://github.com/boto/botocore/blob/develop/botocore/data/organizations/2016-11-28/examples-1.json
    path: /example/,
    content: /example/i,
  },
  {
    id: "vendor",
    description: "Vendor dirs",
    path: /\/vendor\//,
  },
  {
    id: "usr-dirs",
    description: "System dirs",
    path: /^usr\/(?:share|include|lib)\//,
  },
  {
    id: "locale-dir",
    description: "Locales directory contains locales file",
    path: /\/locales?\//,
  },
  {
    id: "markdown",
    description: "Markdown files",
    path: /\.md$/,
  },
  {
    id: "node.js",
    description: "Node container images",
    path: /^opt\/yarn-v[\d.]+\//,
  },
  {
    id: "golang",
    description: "Go container images",
    path: /^usr\/local\/go\//,
  },
  {
    id: "python",
    description: "Python container images",
    path: /^usr\/local\/lib\/python[\d.]+\//,
  },
  {
    id: "rubygems",
    description: "Ruby container images",
    path: /^usr\/lib\/gems\//,
  },
  {
    id: "wordpress",
    description: "Wordpress container images",
    path: /^usr\/src\/wordpress\//,
  },
  {
    id: "anaconda-log",
    description: "Anaconda CI Logs in container images",
    path: /^var\/log\/anaconda\//,
  },
];

export default builtinAllowRules;
