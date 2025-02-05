const { contextBridge, ipcRenderer } = require('electron');


contextBridge.exposeInMainWorld('electronAPI', {
  closeWindow: () => {
    ipcRenderer.send('close-window')
  },
  send: (channel, data) => ipcRenderer.send(channel, data),
  path: {
    dirname: (toolPath) => path.dirname(toolPath),  // 将 path.dirname 暴露给渲染进程
  },
});
