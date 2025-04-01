# BarcCrypt Chrome Extension

A Chrome extension for the BarcCrypt password manager that helps you save and manage passwords securely while browsing.

## Features

- Automatically detects login forms on websites
- Suggests saving passwords when you enter them
- Generates strong passwords
- Auto-fills saved passwords
- Quick access to password management and analysis tools
- Secure password storage with encryption

## Installation

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" in the top right corner
3. Click "Load unpacked" and select the `extension` folder from this repository
4. The BarcCrypt extension icon should appear in your Chrome toolbar

## Usage

### Saving Passwords

1. When you visit a website with a login form, the extension will automatically detect it
2. When you enter a password, a popup will appear asking if you want to save it
3. You can:
   - Save the current password
   - Generate a new strong password
   - Copy the password to clipboard
   - Cancel the operation

### Auto-filling Passwords

1. When you return to a website where you've saved a password
2. The extension will automatically fill in your saved credentials
3. You can also click the extension icon to manually trigger password detection

### Managing Passwords

1. Click the BarcCrypt extension icon
2. Use the "Manage Passwords" button to access your password vault
3. Use the "Analyze Password" button to check password strength

## Security

- All passwords are encrypted before being sent to the server
- Passwords are never stored in plain text
- The extension only communicates with your local BarcCrypt server
- No data is sent to third-party servers

## Requirements

- Chrome browser
- BarcCrypt server running locally (http://localhost:5000)
- Active internet connection for breach checking

## Development

To modify the extension:

1. Make your changes to the source files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the BarcCrypt extension card
4. The changes will be loaded automatically

## File Structure

```
extension/
├── manifest.json      # Extension configuration
├── popup.html        # Extension popup interface
├── popup.js          # Popup functionality
├── content.js        # Content script for webpage interaction
├── background.js     # Background script for extension events
├── styles.css        # Styles for popup and content
└── icons/           # Extension icons
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
``` 