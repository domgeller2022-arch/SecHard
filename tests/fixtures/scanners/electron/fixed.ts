// FIXTURE: isolated, sandboxed Electron renderer with a preload bridge.
const mainWindow = {
  webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, preload: 'preload.js' },
};
export const window = mainWindow;
