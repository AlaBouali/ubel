'use strict';
import processes from './processes.js';
import network from './network.js';
import libraries from './libraries.js';
import components from './components.js';
import secrets from './secrets.js';
import containers from './containers.js';
import inspection from './inspection.js';

/** Every ubel-runtime rule, in the order they run. */
export const rules = [...processes, ...network, ...libraries, ...components, ...secrets, ...containers, ...inspection];
export const AREAS = ['processes', 'exposure', 'libraries', 'components', 'secrets', 'containers', 'inspection'];
