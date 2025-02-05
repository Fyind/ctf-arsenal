const { app, BrowserWindow, ipcMain } = require('electron');
const log = require('electron-log');
const path = require('path');
const { exec, execFile } = require('child_process');

let mainWindow;

log.info('App started');

const windowInfo = {
	width: 1000,
	height: 700,
	webPreferences: {
		// preload: path.join(__dirname, 'preload.js'), // 加载 preload.js
		nodeIntegration: true, // 禁用 Node.js 集成
		contextIsolation: false, // 启用上下文隔离
	},
	frame: false, // Remove the window frame
	titleBarStyle: 'hidden' // Hide the title bar for macOS
}

app.on('ready', () => {
	mainWindow = new BrowserWindow(windowInfo);

	mainWindow.loadFile('src/index.html');

	mainWindow.on('closed', () => {
		mainWindow = null;
	});
});



app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit();
	}
});

app.on('activate', () => {
	if (BrowserWindow.getAllWindows().length === 0) {
		mainWindow = new BrowserWindow(windowInfo);
		mainWindow.loadFile('src/index.html');
	}
});

ipcMain.on('close-window', () => {
	if (mainWindow) {
		mainWindow.close();
	}
});

ipcMain.on('log-message', (event, arg) => {
	log.info(`Received message from renderer: ${arg}`);
});

ipcMain.on('open-exe', (event, exePath) => {
    execFile(exePath, (error, stdout, stderr) => {
      if (error) {
        event.reply('exe-error', `Error: ${error.message}`);
        return;
      }
      event.reply('exe-output', `Output: ${stdout}`);
    });
});

ipcMain.on('run-cmd', (event, command) => {
    // 执行传入的 CMD 命令
exec(command, (error, stdout, stderr) => {
	if (error) {
	event.reply('cmd-error', `Error: ${error.message}`);
	return;
	}
	if (stderr) {
	event.reply('cmd-error', `stderr: ${stderr}`);
	return;
	}
	// 发送命令的输出回渲染进程
	event.reply('cmd-output', `stdout: ${stdout}`);
});
});
