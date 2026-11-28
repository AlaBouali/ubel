'use strict';
// Normalises the "where is this resource" values the three clouds hand back into one vocabulary for a finding's `region`:
//
//   * a region id in the provider's own spelling, lower case (us-east-1, us-central1, westeurope);
//   * '' (empty) for a resource that has no region -- IAM, firewalls, project / subscription settings. That is the convention the
//     report already uses everywhere (stats skip it, the diff treats it as "comparable in every region").
//
// A finding's `region` must never be a zone, a list of regions, a display name, or the other spelling of a region that another finding
// of the same cloud already uses -- otherwise the same region is counted twice and a zone is listed as if it were a region.

// A GCP zone is "<region>-<letter>": us-central1-a, europe-west4-b, northamerica-northeast1-c.
const GCP_ZONE = /^([a-z]+(?:-[a-z]+)*\d+)-[a-z]$/;

/**
 * GCP location -> region.
 *   "us-central1-a"            -> "us-central1"   (a zone: its region)
 *   "projects/p/zones/us-c1-a" -> "us-c1"         (a zone given as a resource path)
 *   "US-CENTRAL1" / "us-central1" -> "us-central1" (Cloud Storage upper-cases regions, Compute and GKE do not)
 *   "US" / "EU" / "NAM4"       -> "us" / "eu" / "nam4" (multi- and dual-regions are locations, not regions; kept as the one thing they are)
 */
function gcpRegion(location) {
  const last = String(location ?? '').trim().split('/').filter(Boolean).pop() || '';
  const id = last.toLowerCase();
  const m = id.match(GCP_ZONE);
  return m ? m[1] : id;
}

/** The zone of a GCP location, or '' when the location is a region (or a multi-region). */
function gcpZone(location) {
  const id = String(location ?? '').trim().split('/').filter(Boolean).pop()?.toLowerCase() || '';
  return GCP_ZONE.test(id) ? id : '';
}

/**
 * Azure location -> region id. ARM returns the id ("eastus") for most resource types and the display name ("East US") for others
 * (App Service, for one), so the same region would otherwise appear as two.
 */
function azureRegion(location) {
  return String(location ?? '').toLowerCase().replace(/[\s_-]+/g, '');
}

export { gcpRegion, gcpZone, azureRegion };
