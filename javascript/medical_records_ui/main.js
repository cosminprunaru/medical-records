const electron = require('electron');
const url = require('url');
const path = require('path');

const {app, BrowserWindow, Menu, ipcMain, nativeImage} = electron;

let mainWindow;
let addWindow;
let errorWindow;

let addWindowOpened = false;

// Set environment
//process.env.NODE_ENV = 'production';

// Listen for the app to be ready
app.on('ready', function() {
    // Create new window
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 900,
        icon: path.join(__dirname, '/assets/icons/png/icon.png')
    });
    // Load the html file into the window
    mainWindow.loadURL(url.format({
        pathname: path.join(__dirname, 'mainWindow.html'),
        protocol: 'file:',
        slashes: true
    }));

    // Quit app when closed
    mainWindow.on('closed', function() {
        app.quit();
    });

    // Build menu from template
    const mainMenu = Menu.buildFromTemplate(mainMenuTemplate);

    // Insert the menu
    Menu.setApplicationMenu(mainMenu);
});

// Handle add window
function createAddWindow() {

    // We don't want more than one window
    // opened at a time as it may lead to errors
    if (addWindowOpened == true) {
        return
    }
    addWindowOpened = true

    // Create new window
    addWindow = new BrowserWindow({
        width: 700,
        height: 400,
        title: 'Add new medical record',
        icon: path.join(__dirname, '/assets/icons/png/icon.png')
    });

    // Load the html file into the window
    addWindow.loadURL(url.format({
        pathname: path.join(__dirname, 'addWindow.html'),
        protocol: 'file:',
        slashes: true
    }));

    // Garbage Collection handle
    addWindow.on('close', function() {
        addWindowOpened = false
        addWindow = null;
    });

}

// Handle error window
function createErrorWindow() {

    // Create new window
    errorWindow = new BrowserWindow({
        width: 400,
        height: 300,
        title: 'Error',
        icon: path.join(__dirname, '/assets/icons/png/icon.png')
    });

    // Load the html file into the window
    errorWindow.loadURL(url.format({
        pathname: path.join(__dirname, 'errorWindow.html'),
        protocol: 'file:',
        slashes: true
    }));

    // Garbage Collection handle
    errorWindow.on('close', function() {
        errorWindow = null;
    });
}

ipcMain.on('record:addFromButton', function(e) {
    createAddWindow()
});

ipcMain.on('record:error', function(e) {
    errorWindow.close()
});

// Catch record:add
ipcMain.on('record:add', function(e, record) {    
    unmarshalledRecord = JSON.parse(record)

    if (unmarshalledRecord.doctor.id == 0) {
        addWindow.close();
        addWindowOpened = false
        return createErrorWindow()
    }

    // pass JSON to main window
    mainWindow.webContents.send('record:add', unmarshalledRecord);
    addWindow.close();
    addWindowOpened = false
});

// Catch record:search
ipcMain.on('record:search', function(e, recordsFound) {
    // send to backend for searching in the db
    unmarshalledRecords = JSON.parse(recordsFound)
    mainWindow.webContents.send('records:found', unmarshalledRecords);
});

// Create menu template
const mainMenuTemplate = [
    {
        label:'File',
        submenu: [
            {
                label: 'Add record',
                accelerator: 'Ctrl+N',
                click() {
                    createAddWindow();
                }
            },
            {
                label: 'Clear records',
                click() {
                    mainWindow.webContents.send('record:clear');
                }
            },
            {
                label: 'Quit',
                accelerator: 'Ctrl+Q',
                click() {
                    app.quit();
                }
            }
        ]
    }
];

// Add developer options if not in production
if (process.env.NODE_ENV !== 'production') {
    mainMenuTemplate.push({
        label: 'Developer Tools',
        submenu: [
            {
                label: 'Toogle DevTools',
                accelerator: 'Ctrl+I',
                click(item, focusedWindow) {
                    focusedWindow.toggleDevTools();
                }
            },
            {
                role: 'reload'
            }
        ]
    })
}