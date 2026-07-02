const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('clamshieldAlert', {
  sendAction: (payload) => ipcRenderer.invoke('clamshield-alert-action', payload),
  log: (payload) => ipcRenderer.invoke('clamshield-alert-log', payload),
  close: () => window.close()
});
