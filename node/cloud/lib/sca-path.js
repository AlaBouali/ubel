'use strict';
// Single source of truth for where the shared `sca` module lives relative
// to this package, so every consumer here (html-report.js's Tailwind/
// Chart.js/Google Fonts assets, history.js's zip helper) points at the
// same place instead of each hardcoding its own relative path.
//
// Layout: cloud-scanner is a module of ubel under the `cloud/` folder,
// with `sca` as ubel's other, pre-existing shared module:
//   ubel/
//     cloud/
//       cloud-scanner/   <- this package
//     sca/                <- shared module (tailwindcss.js, chartjs.js,
//                            googlefonts.js, zip.js, ...)
// From src/lib/*.js that's four levels up (lib -> src -> cloud-scanner ->
// cloud) then into sca/.
const SCA_STATIC_PATH = '../../sca';

export { SCA_STATIC_PATH };
