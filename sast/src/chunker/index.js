'use strict';

import { buildChunks, buildChunksDetailed } from './buildChunks.js';
import { stripComments } from './commentStrippers.js';
import { EXT_FAMILY, DEFAULT_LANGUAGES } from './constants.js';
import { KIND_LABEL, KIND_FENCE_LANG } from './configDetect.js';

export { buildChunks, buildChunksDetailed, stripComments, EXT_FAMILY, DEFAULT_LANGUAGES, KIND_LABEL, KIND_FENCE_LANG };
