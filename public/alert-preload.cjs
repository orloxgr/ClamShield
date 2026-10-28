const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('clamshieldAlert', {
  sendAction: (payload) => ipcRenderer.invoke('clamshield-alert-action', payload),
  log: (payload) => ipcRenderer.invoke('clamshield-alert-log', payload),
  onUpdate: (callback) => ipcRenderer.on('clamshield-alert-update', (_event, threat) => callback(threat)),
  close: () => window.close()
});

contextBridge.exposeInMainWorld('clamshieldLanguage', {
  get: () => ipcRenderer.invoke('clamshield-language'),
  refresh: () => ipcRenderer.invoke('clamshield-language-refresh'),
  onChange: callback => {
    const listener = (_event, pack) => callback(pack);
    ipcRenderer.on('clamshield-language-changed', listener);
    return () => ipcRenderer.removeListener('clamshield-language-changed', listener);
  }
});
