
const path = require('path')
const { ipcRenderer } = require('electron');
const fs = require('fs');

function showTools(category) {
    
    fetch('tool_list.json')
        .then(response => response.json())
        .then(tools => {
            
            const contentArea = document.querySelector('.content-area');
            contentArea.innerHTML = '';
            tools[category].forEach(tool => {
                const toolItem = document.createElement('div');
                toolItem.className = 'tool-item';

                if (tool.path.endsWith("bat")) {
                    toolItem.onclick = ()=> {
                        ipcRenderer.send('run-cmd', tool.path)
                    }
                } else {
                    toolItem.onclick = ()=> {
                        ipcRenderer.send('run-cmd',"start " + tool.path)
                    }
                }
                var iconpath = ""
                if (tool.path.startsWith('tool')) {
                    const iconpath_tmp = path.join(path.dirname(tool.path), 'icon.png')
                    iconpath = iconpath_tmp
                }
                if (tool.path.startsWith('http')){
                    // iconpath = new URL('/favicon.ico', tool.path).href; // 自动拼接 favicon.ico
                    iconpath = `https://www.google.com/s2/favicons?domain=${new URL(tool.path).hostname}&sz=128`;
                }
                
                toolItem.innerHTML = ` 
            <img src="${iconpath}" alt="${tool.name}" />
            <span>${tool.name}</span>
            `;
                contentArea.appendChild(toolItem);
            });
        })
        .catch(error => console.error('Error loading tools:', error));
}