# Security Policy

## Purpose

React2Shell is a security research tool designed for **authorized penetration testing** and **educational purposes only**. This tool exploits CVE-2025-55182, a critical vulnerability in React Server Components.

## Responsible Use

Before using this tool, you MUST:

1. **Have explicit written authorization** from the system owner
2. **Understand the legal implications** in your jurisdiction
3. **Use only in controlled environments** (like the included lab) for learning
4. **Never target production systems** without proper authorization

## Reporting Security Issues

### In This Tool

If you find a security vulnerability in React2Shell itself (not the CVE it exploits), please:

1. **Do NOT open a public issue**
2. Email the maintainer directly with details
3. Allow reasonable time for a fix before public disclosure

### In React/Next.js

CVE-2025-55182 has been patched. If you discover new vulnerabilities:

- **React**: https://github.com/facebook/react/security/advisories
- **Next.js**: https://github.com/vercel/next.js/security/advisories
- **Vercel**: https://vercel.com/security

## Legal Disclaimer

Unauthorized access to computer systems is illegal. This tool is provided for:

- Authorized penetration testing engagements
- Security research with proper authorization
- CTF competitions and security training
- Testing your own systems

The authors are not responsible for any misuse or damage caused by this tool. Users assume all legal responsibility for their actions.

## Affected Versions (CVE-2025-55182)

| Package | Vulnerable | Patched |
|---------|------------|---------|
| React | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1+ |
| Next.js | 13.x-15.x (various) | 14.2.35, 15.1.4, 15.4.8+ |
| react-server-dom-webpack | 19.0.0-19.2.0 | 19.2.1+ |

## References

- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Next.js Security Advisory](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp)
- [CVE-2025-55182 Details](https://www.facebook.com/security/advisories/cve-2025-55182)
