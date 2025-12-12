// background.js - Manages extension state and dynamic header rules

const RULE_ID = 1;

// Add header modification rule for a specific domain
async function enableHeaderRules(domain) {
    try {
        // Remove any existing rule first
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [RULE_ID]
        });

        // Add rule scoped to specific domain
        await chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [{
                id: RULE_ID,
                priority: 1,
                action: {
                    type: "modifyHeaders",
                    requestHeaders: [
                        { header: "Origin", operation: "remove" }
                    ]
                },
                condition: {
                    urlFilter: `*://${domain}/*`,
                    resourceTypes: ["xmlhttprequest"]
                }
            }]
        });
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// Remove header modification rules
async function disableHeaderRules() {
    try {
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [RULE_ID]
        });
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// Get current settings
async function getSettings() {
    const defaults = {
        enabled: true,
        exploitPath: "/adfa",
        confirmExploit: true
    };
    const stored = await chrome.storage.local.get(defaults);
    return stored;
}

// Save settings
async function saveSettings(settings) {
    await chrome.storage.local.set(settings);
    return { success: true };
}

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Badge update from content script
    if (request.action === "update_badge" && sender.tab) {
        chrome.action.setBadgeBackgroundColor({
            tabId: sender.tab.id,
            color: "#FF0000"
        });
        chrome.action.setBadgeText({
            tabId: sender.tab.id,
            text: "!"
        });
    }

    // Enable header rules for exploit
    if (request.action === "enable_header_rules") {
        enableHeaderRules(request.domain).then(sendResponse);
        return true;
    }

    // Disable header rules after exploit
    if (request.action === "disable_header_rules") {
        disableHeaderRules().then(sendResponse);
        return true;
    }

    // Get settings
    if (request.action === "get_settings") {
        getSettings().then(sendResponse);
        return true;
    }

    // Save settings
    if (request.action === "save_settings") {
        saveSettings(request.settings).then(sendResponse);
        return true;
    }
});

// Clear rules on startup
chrome.runtime.onStartup.addListener(() => {
    disableHeaderRules();
});

// Clear rules on install/update
chrome.runtime.onInstalled.addListener(() => {
    disableHeaderRules();
});
