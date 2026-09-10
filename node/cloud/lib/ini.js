'use strict';

/**
 * Minimal INI parser, just enough for AWS-style credentials/config files:
 *   [default]
 *   aws_access_key_id = AKIA...
 *   aws_secret_access_key = ...
 *
 *   [profile work]
 *   region = eu-west-1
 */
function parseIni(text) {
  const result = {};
  let section = null;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;

    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1].replace(/^profile\s+/, '').trim();
      if (!result[section]) result[section] = {};
      continue;
    }

    const kvMatch = line.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (kvMatch && section) {
      const [, key, value] = kvMatch;
      result[section][key.trim()] = value.trim();
    }
  }

  return result;
}

export { parseIni };
