'use strict';
import ssh from './ssh.js';
import accounts from './accounts.js';
import filesystem from './filesystem.js';
import kernel from './kernel.js';
import network from './network.js';
import services from './services.js';
import logging from './logging.js';
import os from './os.js';
import secrets from './secrets.js';
import boot from './boot.js';
import k8snode from './k8snode.js';

/** Every ubel-vm rule, in the order they run. */
export const rules = [...os, ...ssh, ...accounts, ...filesystem, ...kernel, ...network, ...services, ...logging, ...secrets, ...boot, ...k8snode];
export const AREAS = ['os', 'ssh', 'accounts', 'filesystem', 'kernel', 'network', 'services', 'logging', 'secrets', 'boot', 'kubernetes'];
