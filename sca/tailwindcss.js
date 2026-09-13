import { readFile } from 'node:fs/promises';

export async function getTailwindScript() {
  const content = await readFile(new URL("./tailwindcss.jstxt", import.meta.url), "utf8");
  return content;
}
