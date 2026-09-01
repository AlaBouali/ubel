import { readFile } from 'node:fs/promises';

export async function getChartJSScript() {
  const content = await readFile(new URL("./chartjs.jstxt", import.meta.url), "utf8");
  return content;
}
