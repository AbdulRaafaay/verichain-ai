'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
    auth: {
        isEnrolled: () => ipcRenderer.invoke('auth:is-enrolled'),
        enroll: () => ipcRenderer.invoke('auth:enroll'),
        login: (data) => ipcRenderer.invoke('auth:login', data),
    },
    system: {
        getStatus: () => ipcRenderer.invoke('system:get-status'),
        getTelemetry: () => ipcRenderer.invoke('system:get-telemetry'),
    }
});
