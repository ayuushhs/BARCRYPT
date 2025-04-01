// Listen for when the extension icon is clicked
chrome.action.onClicked.addListener(async (tab) => {
    try {
        // Check if we can inject into this tab
        if (!tab.url.startsWith('chrome:') && !tab.url.startsWith('edge:')) {
            // Execute content script first if not already injected
            await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content.js']
            });

            // Then send the message
            await chrome.tabs.sendMessage(tab.id, { action: 'checkLoginForm' });
        }
    } catch (error) {
        console.log('Error:', error.message);
    }
});

// Listen for when a tab is updated
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
        // When the page is fully loaded
        if (changeInfo.status === 'complete' && 
            !tab.url.startsWith('chrome:') && 
            !tab.url.startsWith('edge:')) {
            
            // Execute content script first if not already injected
            await chrome.scripting.executeScript({
                target: { tabId: tabId },
                files: ['content.js']
            });

            // Then send the message
            await chrome.tabs.sendMessage(tabId, { action: 'checkLoginForm' });
        }
    } catch (error) {
        console.log('Error:', error.message);
    }
}); 