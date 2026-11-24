'use strict';
import { na } from '../../vm/lib/engine.js';
export { rule } from '../lib/util.js';

/** Every rule needs /proc; on anything else the whole catalogue is "not applicable", never "clean". */
export const needLive = (ctx) => (ctx.live ? null : na(`needs a live Linux host with /proc (this is ${process.platform}${process.platform === 'linux' ? ', /proc is not readable' : ''})`));
