const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('clamshieldResultsReminder', {
  sendAction: (payload) => ipcRenderer.invoke('clamshield-results-reminder-action', payload)
});
