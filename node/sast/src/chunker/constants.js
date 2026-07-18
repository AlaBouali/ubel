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
};

const DEFAULT_LANGUAGES = ['js', 'php', 'python', 'rust', 'go', 'ruby', 'java', 'kotlin', 'csharp', 'c'];

export {
  SUPPORTED_EXTENSIONS,
  IGNORE_DIRS,
  EXT_FAMILY,
  FAMILY_LABELS,
  LANGUAGE_ALIASES,
  DEFAULT_LANGUAGES,
};