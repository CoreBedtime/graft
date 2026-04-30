import ObjC from './vendor/frida-objc-bridge/index.js';

globalThis.ObjC = ObjC;

import './agent/bootstrap.js';
