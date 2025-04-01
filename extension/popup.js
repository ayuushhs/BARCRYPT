document.addEventListener('DOMContentLoaded', () => {
    // Get the current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentTab = tabs[0];
        
        // Handle Manage Passwords button click
        document.getElementById('manageBtn').addEventListener('click', () => {
            chrome.tabs.create({
                url: 'http://localhost:5000/manage'
            });
        });
        
        // Handle Analyze Password button click
        document.getElementById('analyzeBtn').addEventListener('click', () => {
            chrome.tabs.create({
                url: 'http://localhost:5000/analyze'
            });
        });
    });
}); 