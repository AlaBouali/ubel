import { readFile } from 'node:fs/promises';

export async function getGoogleFontsScript() {
  const content = await readFile(new URL("./googlefonts.jstxt", import.meta.url), "utf8");
  return content;
}
