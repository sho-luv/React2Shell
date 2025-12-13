# CVE-2025-55182 Learning Path

A comprehensive guide to understanding and exploiting React Server Components vulnerabilities.

---

## About This Vulnerability

**CVE-2025-55182** is a critical unauthenticated Remote Code Execution vulnerability affecting React Server Components.

| | |
|-|-|
| **CVSS Score** | 10.0 (Critical) |
| **Impact** | Unauthenticated RCE |
| **Disclosed** | December 3, 2025 |
| **Affected** | React 19.0-19.2.0, Next.js, Waku, React Router |

An attacker can execute arbitrary commands on any vulnerable server with a single HTTP request. No authentication required.

---

## Learning Path

This documentation is structured as a progressive learning experience. Start from the beginning and work through each chapter.

### [Chapter 1: Fundamentals](01-fundamentals.md)
**Prerequisites:** Basic JavaScript knowledge

Learn the building blocks:
- What are React Server Components?
- The Flight protocol and serialization
- Prototype pollution basics
- Server Actions in Next.js

### [Chapter 2: The Vulnerability](02-vulnerability.md)
**Prerequisites:** Chapter 1

Understand CVE-2025-55182:
- The vulnerable `getOutlinedModel` function
- How path traversal reaches the prototype
- The complete exploit chain
- Why this vulnerability is so dangerous

### [Chapter 3: Exploitation](03-exploitation.md)
**Prerequisites:** Chapter 2

Hands-on exploitation:
- Payload structure breakdown
- Understanding each form field
- Writing RCE code
- Manual exploitation walkthrough
- Using the CLI tool

### [Chapter 4: Framework Differences](04-frameworks.md)
**Prerequisites:** Chapter 3

Adapting to different targets:
- Next.js (CommonJS, easy)
- React Router (ESM, medium)
- Waku (blind RCE, hard)
- Universal payload patterns

### [Chapter 5: Defense & Detection](05-defense.md)
**Prerequisites:** Chapters 1-4

Protecting your applications:
- Patching and version checking
- Detection techniques
- WAF rules (and their limitations)
- Incident response
- Understanding the fix

---

## Quick Start

### Start the Lab

```bash
cd ../lab
docker-compose up -d
```

### Exploitable Targets

| Port | Framework | Difficulty | Output |
|------|-----------|------------|--------|
| 3011 | Next.js | Easy | HTTP header |
| 3014 | Waku | Hard | Blind RCE |
| 3015 | React Router | Medium | HTTP header |

### Run Your First Exploit

```bash
# After completing Chapter 3
python cli/react2shell.py http://localhost:3011 -c "id"
```

---

## Who Is This For?

- **Security researchers** learning about prototype pollution and RCE
- **Penetration testers** needing to test for CVE-2025-55182
- **Developers** wanting to understand the vulnerability to defend against it
- **CTF players** practicing web exploitation techniques
- **Students** learning about modern JavaScript security

---

## Prerequisites

- Basic JavaScript knowledge
- Understanding of HTTP requests
- Docker installed (for lab environment)
- Python 3.8+ (for CLI tool)

---

## Time Investment

| Chapter | Reading | Hands-On | Total |
|---------|---------|----------|-------|
| 1. Fundamentals | 15 min | 15 min | 30 min |
| 2. Vulnerability | 20 min | 10 min | 30 min |
| 3. Exploitation | 15 min | 30 min | 45 min |
| 4. Frameworks | 15 min | 20 min | 35 min |
| 5. Defense | 15 min | 15 min | 30 min |
| **Total** | | | **~3 hours** |

---

## Additional Resources

### External Links
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Wiz Blog - React2Shell](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)

### Tools
- [React2Shell CLI](../cli/) - Scanner and exploit tool
- [Lab Environment](../lab/) - Practice targets
- [Nuclei Template](../nuclei/) - Mass scanning

---

## Ready to Begin?

**[Start Chapter 1: Fundamentals →](01-fundamentals.md)**
