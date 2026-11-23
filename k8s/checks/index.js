'use strict';
import workload from './workload.js';
import rbac from './rbac.js';
import network from './network.js';
import cluster from './cluster.js';

/** Every ubel-k8s rule, in the order they run. */
export const rules = [...workload, ...rbac, ...network, ...cluster];
