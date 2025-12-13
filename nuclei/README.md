# Nuclei Templates for CVE-2025-55182

Nuclei templates for detecting React Server Components RCE vulnerability.

## Templates

| Template | Method | Risk |
|----------|--------|------|
| `CVE-2025-55182.yaml` | Math operation RCE | Executes code on target |
| `CVE-2025-55182-safe.yaml` | Side-channel detection | No code execution |

## Usage

```bash
# Safe detection (recommended for production scanning)
nuclei -t CVE-2025-55182-safe.yaml -u https://target.com

# RCE verification (use only on authorized targets)
nuclei -t CVE-2025-55182.yaml -u https://target.com

# Scan multiple targets with safe template
nuclei -t CVE-2025-55182-safe.yaml -l targets.txt

# With rate limiting
nuclei -t CVE-2025-55182-safe.yaml -u https://target.com -rl 10
```

## Template Details

### CVE-2025-55182.yaml (RCE Verification)
- Executes a math operation on the target
- Verifies the result via X-Action-Redirect header
- **Use only on systems you have permission to test**

### CVE-2025-55182-safe.yaml (Safe Detection)
- Uses invalid property path to trigger error
- Checks for vulnerable error response patterns
- Detects platform mitigations (Vercel, Netlify)
- **Recommended for production scanning**

## Requirements

- [Nuclei](https://github.com/projectdiscovery/nuclei) v2.0+

## Installation

```bash
# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download from releases
# https://github.com/projectdiscovery/nuclei/releases
```

## Security Note

These templates are intended for authorized security testing only.
