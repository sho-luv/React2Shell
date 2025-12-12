# Nuclei Templates for CVE-2025-55182

Nuclei templates for detecting React Server Components RCE vulnerability.

## Usage

```bash
# Scan single target
nuclei -t CVE-2025-55182.yaml -u https://target.com

# Scan multiple targets
nuclei -t CVE-2025-55182.yaml -l targets.txt

# With rate limiting
nuclei -t CVE-2025-55182.yaml -u https://target.com -rl 10
```

## Template Details

The template checks for CVE-2025-55182 using:
- Safe side-channel detection (no code execution)
- Checks for vulnerable error response patterns
- Detects platform mitigations (Vercel, Netlify)

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

This template is intended for authorized security testing only.
