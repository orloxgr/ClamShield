const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('clamshieldAlert', {
  sendAction: (payload) => ipcRenderer.invoke('clamshield-alert-action', payload),
  log: (payload) => ipcRenderer.invoke('clamshield-alert-log', payload),
  onUpdate: (callback) => ipcRenderer.on('clamshield-alert-update', (_event, threat) => callback(threat)),
  close: () => window.close()
});
