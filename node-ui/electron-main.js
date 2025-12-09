const { app, BrowserWindow } = require("electron");
const { start, PORT } = require("./web-server");

function createWindow() {
  const win = new BrowserWindow({
    width: 1020,
    height: 760,
    backgroundColor: "#0f1115",
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadURL(`http://127.0.0.1:${PORT}/`);
}

app.whenReady().then(() => {
  start();
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
