// FIXTURE: unsafe Electron renderer configuration.
const mainWindow = {
  webPreferences: { nodeIntegration: true, contextIsolation: false, sandbox: false },
};
export const window = mainWindow;
