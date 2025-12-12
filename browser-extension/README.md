# React2Shell Browser Extension

A Chrome extension for detecting CVE-2025-55182 (React Server Components RCE) vulnerabilities in Next.js applications.

## Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select this `browser-extension` directory

## Features

- **Auto-detection**: Automatically scans pages for RSC vulnerability indicators
- **Manual scanning**: Click the extension icon to scan the current page
- **Configurable path**: Set custom exploit paths for different applications
- **Enable/Disable toggle**: Turn scanning on/off as needed
- **Visual indicators**: Clear vulnerable/safe status display

## Usage

1. Navigate to a Next.js application
2. Click the React2Shell extension icon
3. The extension will automatically check for vulnerability indicators
4. If vulnerable, you can use the command execution feature

## Files

- `manifest.json` - Extension configuration
- `background.js` - Service worker for dynamic header rules
- `content.js` - Content script for page scanning
- `popup.html` - Extension popup UI
- `popup.js` - Popup functionality
- `images/` - Extension icons

## Security Note

This tool is intended for authorized security testing only. Do not use against systems without explicit permission.
