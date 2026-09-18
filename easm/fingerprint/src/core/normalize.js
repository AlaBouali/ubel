import { buildCpeIds, buildPurlIds } from "./componentId.js";
import { CpeParser } from "./cpeParser.js";

/**
 * @param {{product?: string|string[], vendor?: string|string[], version?: string, source?: string, port?: number|string, purl?: {ecosystem: string, name: string, namespace?: string}}} component
 * @returns {{Ids: string[], Name: string, Version: string, Host: string, Port: number|string|null, Tags: string[]}}
 */
export function normalizeComponent(component) {
  const name =
    component.product && component.vendor
      ? CpeParser.getProductName({ product: component.product, vendor: component.vendor }, false)
      : component.product || component.vendor || "";

  return {
    // CPE ids (possibly several, one per vendor/product alias) plus at most
    // one purl id when the scanner set component.purl — see componentId.js.
    // Both kinds flow through scan.js's lookup loop and get attributed back
    // to the same inventory item, so a component isn't forced to pick one
    // identifier scheme over the other.
    Ids: [...buildCpeIds(component), ...buildPurlIds(component)],
    Name: name,
    Version: component.version || "",
    Host: component.source || "",
    Port: component.port ?? null,
    // Carried through verbatim so downstream consumers (e.g. easm/lib/scan.js's
    // WordPress plugin/theme detection) can tell what kind of component this
    // is without re-parsing the CPE id. buildCpeIds() above already reads
    // component.tags for the same reason (o vs a CPE type), so this is
    // exposing data the pipeline already has, not adding new detection.
    Tags: component.tags || [],
  };
}

/** @param {object[]} components */
export function normalizeComponents(components) {
  return (components || []).map(normalizeComponent);
}