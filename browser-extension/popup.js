// popup.js - UI logic for React2Shell

document.addEventListener('DOMContentLoaded', () => {
    const el = {
        // Main toggle
        masterToggle: document.getElementById('masterToggle'),
        mainContainer: document.getElementById('mainContainer'),

        // Passive detection
        passiveBadge: document.getElementById('passive-badge'),
        passiveList: document.getElementById('passive-list'),
        passiveScore: document.getElementById('passive-score'),

        // Active fingerprint
        btnFinger: document.getElementById('btnFingerprint'),
        fingerResult: document.getElementById('fingerprint-result'),
        activeList: document.getElementById('active-list'),

        // Exploit
        btnExploit: document.getElementById('btnExploit'),
        pathInput: document.getElementById('pathInput'),
        cmdInput: document.getElementById('cmdInput'),
        exploitStatus: document.getElementById('exploit-status'),
        exploitResult: document.getElementById('exploit-result'),
        rceOutput: document.getElementById('rce-output'),
        btnCopy: document.getElementById('btnCopy'),

        // Settings
        confirmExploit: document.getElementById('confirmExploit'),

        // Confirmation dialog
        confirmOverlay: document.getElementById('confirmOverlay'),
        confirmTarget: document.getElementById('confirmTarget'),
        confirmCmd: document.getElementById('confirmCmd'),
        btnCancelExploit: document.getElementById('btnCancelExploit'),
        btnConfirmExploit: document.getElementById('btnConfirmExploit'),

        // Cards
        passiveCard: document.getElementById('passiveCard'),
        fingerprintCard: document.getElementById('fingerprintCard'),
        exploitCard: document.getElementById('exploitCard')
    };

    let currentTabId = null;
    let currentDomain = null;
    let pendingExploit = null;

    // Load settings
    chrome.runtime.sendMessage({ action: "get_settings" }, (settings) => {
        if (settings) {
            el.masterToggle.checked = settings.enabled !== false;
            el.pathInput.value = settings.exploitPath || "/adfa";
            el.confirmExploit.checked = settings.confirmExploit !== false;
            updateEnabledState();
        }
    });

    // Master toggle handler
    el.masterToggle.addEventListener('change', () => {
        updateEnabledState();
        saveSettings();
    });

    function updateEnabledState() {
        const enabled = el.masterToggle.checked;
        const cards = [el.passiveCard, el.fingerprintCard, el.exploitCard];
        cards.forEach(card => {
            if (enabled) {
                card.classList.remove('disabled');
            } else {
                card.classList.add('disabled');
            }
        });
    }

    // Save settings
    function saveSettings() {
        chrome.runtime.sendMessage({
            action: "save_settings",
            settings: {
                enabled: el.masterToggle.checked,
                exploitPath: el.pathInput.value,
                confirmExploit: el.confirmExploit.checked
            }
        });
    }

    // Settings change handlers
    el.confirmExploit.addEventListener('change', saveSettings);
    el.pathInput.addEventListener('change', saveSettings);

    // Get current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        currentTabId = tabs[0].id;
        currentDomain = new URL(tabs[0].url).hostname;

        // Initialize passive scan display
        chrome.tabs.sendMessage(currentTabId, { action: "get_passive" }, (res) => {
            if (chrome.runtime.lastError || !res) {
                el.passiveBadge.innerText = "ERROR";
                el.passiveBadge.className = "badge orange";
                el.passiveList.innerHTML = "<li>Please refresh page</li>";
                return;
            }

            if (res.isRSC) {
                el.passiveBadge.innerText = "DETECTED";
                el.passiveBadge.className = "badge red";
            } else {
                el.passiveBadge.innerText = "SAFE";
                el.passiveBadge.className = "badge green";
            }

            el.passiveList.innerHTML = "";
            if (res.details.length === 0) {
                el.passiveList.innerHTML = "<li>No patterns found</li>";
            }
            res.details.forEach(d => {
                const li = document.createElement('li');
                li.innerText = d;
                li.style.color = "#c0392b";
                el.passiveList.appendChild(li);
            });

            if (res.score !== undefined) {
                el.passiveScore.innerText = `Confidence score: ${res.score}`;
            }
        });

        // Fingerprint button handler
        el.btnFinger.addEventListener('click', () => {
            if (!el.masterToggle.checked) return;

            el.btnFinger.disabled = true;
            el.btnFinger.innerText = "Probing...";
            el.fingerResult.style.display = 'none';

            chrome.tabs.sendMessage(currentTabId, { action: "run_fingerprint" }, (res) => {
                el.btnFinger.disabled = false;
                el.btnFinger.innerText = "Start Fingerprint Probe";
                el.fingerResult.style.display = 'block';
                el.activeList.innerHTML = "";

                if (res && res.detected) {
                    res.details.forEach(d => {
                        const li = document.createElement('li');
                        li.innerText = d;
                        li.style.color = "#d35400";
                        li.style.fontWeight = "bold";
                        el.activeList.appendChild(li);
                    });
                } else if (res && res.error) {
                    el.activeList.innerHTML = `<li style='color:#e74c3c'>${res.details[0]}</li>`;
                } else {
                    el.activeList.innerHTML = "<li style='color:#27ae60'>No Active RSC Response</li>";
                }
            });
        });

        // Exploit button handler
        el.btnExploit.addEventListener('click', () => {
            if (!el.masterToggle.checked) return;

            const cmd = el.cmdInput.value || "whoami";
            const path = el.pathInput.value || "/adfa";

            if (el.confirmExploit.checked) {
                // Show confirmation dialog
                pendingExploit = { cmd, path };
                el.confirmTarget.innerText = `${currentDomain}${path}`;
                el.confirmCmd.innerText = cmd;
                el.confirmOverlay.style.display = 'block';
            } else {
                executeExploit(cmd, path);
            }
        });

        // Confirmation dialog handlers
        el.btnCancelExploit.addEventListener('click', () => {
            el.confirmOverlay.style.display = 'none';
            pendingExploit = null;
        });

        el.btnConfirmExploit.addEventListener('click', () => {
            el.confirmOverlay.style.display = 'none';
            if (pendingExploit) {
                executeExploit(pendingExploit.cmd, pendingExploit.path);
                pendingExploit = null;
            }
        });

        // Close dialog on overlay click
        el.confirmOverlay.addEventListener('click', (e) => {
            if (e.target === el.confirmOverlay) {
                el.confirmOverlay.style.display = 'none';
                pendingExploit = null;
            }
        });

        // Execute exploit function
        async function executeExploit(cmd, path) {
            el.btnExploit.disabled = true;
            el.exploitStatus.style.display = 'block';
            el.exploitResult.style.display = 'none';

            // Enable header rules for this domain
            await new Promise(resolve => {
                chrome.runtime.sendMessage({
                    action: "enable_header_rules",
                    domain: currentDomain
                }, resolve);
            });

            chrome.tabs.sendMessage(currentTabId, {
                action: "run_exploit",
                cmd: cmd,
                path: path
            }, async (res) => {
                // Disable header rules after exploit
                await new Promise(resolve => {
                    chrome.runtime.sendMessage({ action: "disable_header_rules" }, resolve);
                });

                el.btnExploit.disabled = false;
                el.exploitStatus.style.display = 'none';
                el.exploitResult.style.display = 'block';

                if (res && res.success) {
                    el.rceOutput.style.color = "#00cec9";
                    el.rceOutput.innerText = `[+] Target: ${currentDomain}${res.path}\n[+] Command: ${res.command}\n[+] Output:\n${res.output}`;
                    chrome.runtime.sendMessage({ action: "update_badge" });
                } else {
                    el.rceOutput.style.color = "#e74c3c";
                    let errorMsg = `[-] ${res ? res.msg : "Unknown error"}`;
                    if (res && res.suggestion) {
                        errorMsg += `\n[!] Suggestion: ${res.suggestion}`;
                    }
                    if (res && res.debug) {
                        errorMsg += `\n[DEBUG] ${res.debug}`;
                    }
                    el.rceOutput.innerText = errorMsg;
                }
            });
        }

        // Copy button handler
        el.btnCopy.addEventListener('click', () => {
            const text = el.rceOutput.innerText;
            navigator.clipboard.writeText(text).then(() => {
                el.btnCopy.innerText = "Copied!";
                el.btnCopy.classList.add('copied');
                setTimeout(() => {
                    el.btnCopy.innerText = "Copy";
                    el.btnCopy.classList.remove('copied');
                }, 1500);
            });
        });
    });
});
