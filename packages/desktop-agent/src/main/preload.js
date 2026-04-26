'use strict';

const { contextBridge, ipcRenderer } = require('electron');

/**
 * preload.js — Secure bridge between Electron main process and React renderer.
 * Only explicitly listed channels are exposed (no direct Node access from renderer).
 */
contextBridge.exposeInMainWorld('electron', {
    auth: {
        isEnrolled: ()       => ipcRenderer.invoke('auth:is-enrolled'),
        enroll:     ()       => ipcRenderer.invoke('auth:enroll'),
        login:      (data)   => ipcRenderer.invoke('auth:login', data),
    },
    resource: {
        /** Request access to a protected resource. Options: { resourceId, accessVelocity, geoDistanceKm, uniqueResources, downloadBytes, timeSinceLast, deviceIdMatch } */
        access: (options) => ipcRenderer.invoke('resource:access', options),
    },
    system: {
        getStatus:    () => ipcRenderer.invoke('system:get-status'),
        getTelemetry: () => ipcRenderer.invoke('system:get-telemetry'),
    },
    onSessionRevoked: (callback) => {
        ipcRenderer.on('session:revoked', (_event, data) => callback(data));
    },
});
