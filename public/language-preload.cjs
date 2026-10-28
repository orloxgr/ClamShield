const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('clamshieldLanguage', {
  get: () => ipcRenderer.invoke('clamshield-language'),
  refresh: () => ipcRenderer.invoke('clamshield-language-refresh'),
  onChange: callback => {
    const listener = (_event, pack) => callback(pack);
    ipcRenderer.on('clamshield-language-changed', listener);
    return () => ipcRenderer.removeListener('clamshield-language-changed', listener);
  }
});
