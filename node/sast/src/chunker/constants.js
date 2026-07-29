'use strict';

// ─── Supported languages ───────────────────────────────────────────────────────

const SUPPORTED_EXTENSIONS = new Set([
  '.py',
  '.js', '.ts', '.mjs', '.cjs',
  '.php',
  '.rb',
  '.go',
  '.rs',
  '.java',
  '.kt', '.kts',
  '.cs',
  '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx',
  '.tf', '.tfvars',
  // .yaml/.yml/.json are deliberately NOT listed here — those extensions are
  // shared with countless non-IaC files, so Kubernetes/CloudFormation/Ansible
  // membership is decided by content sniff (see configDetect.js) rather than
  // extension alone. Dockerfile/Compose have no reliable extension either
  // and are matched by filename instead — see configDetect.js.
]);

const IGNORE_DIRS = new Set([
  'node_modules', '.nyc_output',
  '__pycache__', '.mypy_cache', '.pytest_cache', '.tox',
  'venv', '.venv', 'env', '.env', 'eggs', '.eggs', 'htmlcov',
  'dist', 'build', 'out', 'target', 'bin', 'obj',
  'vendor',
  '.gradle', '.idea', '.vs', 'packages',
  '.git', '.svn', '.hg',
  'coverage',
  '.terraform',
]);

const EXT_FAMILY = {
  '.py':  'python',
  '.js':  'js',  '.ts':  'js',  '.mjs': 'js',  '.cjs': 'js',
  '.php': 'php',
  '.rb':  'ruby',
  '.go':  'go',
  '.rs':  'rust',
  '.java':'java',
  '.kt':  'kotlin', '.kts': 'kotlin',
  '.cs':  'csharp',
  '.c':   'c',   '.h':   'c',
  '.cpp': 'c',   '.cc':  'c',   '.cxx': 'c',
  '.hpp': 'c',   '.hh':  'c',   '.hxx': 'c',
  '.tf':  'iac', '.tfvars': 'iac',
  // Dockerfile/Compose (no reliable extension) and .yaml/.yml/.json-based
  // Kubernetes/CloudFormation/Ansible (ambiguous extension, needs content
  // sniff) are NOT resolvable from extension alone — see configDetect.js.
  // buildChunks.js and dispatcher.js fall back to detectConfigKind() for
  // any file this table doesn't cover.
};

// Language family name → canonical label used in --languages filter
const FAMILY_LABELS = {
  js:     'js',
  python: 'python',
  php:    'php',
  ruby:   'ruby',
  go:     'go',
  rust:   'rust',
  java:   'java',
  kotlin: 'kotlin',
  csharp: 'csharp',
  c:      'c',
  docker: 'docker',
  iac:    'iac',
  k8s:    'k8s',
};

// Aliases accepted on the CLI / opts.languages
const LANGUAGE_ALIASES = {
  javascript: 'js', typescript: 'js', ts: 'js',
  mjs: 'js', cjs: 'js',
  py: 'python',
  rb: 'ruby',
  rs: 'rust',
  kt: 'kotlin', kts: 'kotlin',
  cs: 'csharp', 'c#': 'csharp', dotnet: 'csharp', '.net': 'csharp',
  net: 'csharp',
  cpp: 'c', 'c++': 'c', cxx: 'c', cc: 'c',
  dockerfile: 'docker', compose: 'docker', 'docker-compose': 'docker',
  terraform: 'iac', tf: 'iac', hcl: 'iac',
  cloudformation: 'iac', cfn: 'iac',
  ansible: 'iac',
  // Kubernetes gets its own family, same treatment as docker above, rather
  // than being folded into the generic iac bucket — a `--languages k8s`
  // selection now targets Kubernetes manifests only, not every Terraform/
  // CloudFormation/Ansible file in the repo too.
  kubernetes: 'k8s', k8s: 'k8s',
};

const DEFAULT_LANGUAGES = ['js', 'php', 'python', 'rust', 'go', 'ruby', 'java', 'kotlin', 'csharp', 'c', 'docker', 'iac', 'k8s'];

export {
  SUPPORTED_EXTENSIONS,
  IGNORE_DIRS,
  EXT_FAMILY,
  FAMILY_LABELS,
  LANGUAGE_ALIASES,
  DEFAULT_LANGUAGES,
};