# Chapter 5: Defense & Detection

Now that you understand the attack, let's learn how to defend against it and detect exploitation attempts.

---

## Patching: The Only Real Fix

**WAF rules are NOT sufficient.** The payload can be obfuscated in countless ways. You must patch.

### Patch Versions

| Framework | Vulnerable | Patched |
|-----------|------------|---------|
| React | 19.0.0 - 19.2.0 | 19.0.1, 19.1.2, 19.2.1+ |
| Next.js | 13.4+ - 15.4.7 | 14.2.35, 15.1.4, 15.4.8+ |
| Waku | < 0.27.2 | 0.27.2+ |
| React Router | v7 with RSC | Check for updates |

### How to Check Your Version

```bash
# Next.js
npm list next

# React
npm list react

# Check package-lock.json for exact versions
grep -A1 '"react"' package-lock.json
```

### The npm Retroactive Patch

An interesting discovery: npm can modify already-published packages. After the CVE was disclosed, researchers found that previously vulnerable versions were retroactively patched.

```bash
# These versions were patched AFTER initial publication:
# - react@19.0.0 (original tarball replaced)
# - react@19.1.0 (original tarball replaced)
```

**Lesson:** Even if you "didn't update," you might be protected if you reinstalled dependencies after the patch date.

---

## Detection: Finding Exploitation Attempts

### Log Analysis

Look for these indicators in your logs:

```bash
# Suspicious patterns in request bodies
grep -E "__proto__|constructor|process\.(mainModule|getBuiltinModule)" access.log

# Next-Action header with unusual values
grep "Next-Action" access.log | grep -v "typical-action-id"

# RSC endpoints receiving POST requests
grep "POST.*/_rsc\|POST.*RSC/F" access.log
```

### WAF Rules (Defense in Depth)

While not sufficient alone, WAF rules add a layer:

```yaml
# Example ModSecurity rules
SecRule REQUEST_BODY "@contains __proto__" \
  "id:100001,deny,msg:'Prototype pollution attempt'"

SecRule REQUEST_BODY "@contains constructor:constructor" \
  "id:100002,deny,msg:'Function constructor access attempt'"

SecRule REQUEST_BODY "@rx process\.(mainModule|getBuiltinModule)" \
  "id:100003,deny,msg:'Node.js module access attempt'"
```

### Network-Level Detection

Monitor for:

1. **Unusual outbound connections** from web servers
2. **DNS queries** to unknown domains (OOB exfiltration)
3. **Reverse shell patterns** (unexpected TCP connections)

```bash
# Example: Monitor for suspicious processes
ps aux | grep -E "nc|bash -i|/dev/tcp"

# Check for unexpected listeners
netstat -tlnp | grep -v "expected_ports"
```

---

## Runtime Protection

### Process Isolation

Run Node.js with minimal privileges:

```bash
# Don't run as root
node --user=nobody app.js

# Use containers with read-only filesystem
docker run --read-only --user 1000 myapp
```

### Node.js Security Flags

```bash
# Disable deprecated features
node --disable-proto=delete app.js

# Restrict file system access (experimental)
node --experimental-permission --allow-fs-read=/app app.js
```

### Monitoring Child Processes

The exploit typically spawns child processes. Monitor for this:

```javascript
// In your application
const originalSpawn = require('child_process').spawn;
require('child_process').spawn = function(...args) {
  console.warn('Child process spawned:', args[0]);
  // Could alert, block, or log
  return originalSpawn.apply(this, args);
};
```

---

## Incident Response

If you suspect exploitation:

### 1. Immediate Actions

```bash
# Check for suspicious processes
ps aux | grep -E "nc|curl|wget|bash"

# Check for new files in /tmp
ls -la /tmp/

# Check for unauthorized cron jobs
crontab -l
cat /etc/cron.*/*
```

### 2. Log Collection

```bash
# Preserve logs before rotation
cp /var/log/nginx/access.log /secure/incident/
cp /var/log/application.log /secure/incident/

# Get container logs
docker logs myapp > /secure/incident/docker.log 2>&1
```

### 3. Forensic Indicators

Look for:
- Files named `r2s_out.txt` or similar (React2Shell default)
- Base64-encoded data in redirect headers
- Unexpected environment variable access
- Database queries from unexpected sources

---

## Hardening Checklist

Use this checklist to secure your RSC application:

### Development
- [ ] Use latest patched framework versions
- [ ] Run `npm audit` regularly
- [ ] Review dependencies for RSC usage

### Deployment
- [ ] Run as non-root user
- [ ] Use read-only container filesystems where possible
- [ ] Implement network segmentation
- [ ] Deploy WAF with prototype pollution rules

### Monitoring
- [ ] Log all incoming requests with bodies
- [ ] Alert on `__proto__` or `constructor` in requests
- [ ] Monitor for child process spawning
- [ ] Track outbound network connections

### Response
- [ ] Have incident response plan ready
- [ ] Know how to quickly patch/rollback
- [ ] Maintain offline backups

---

## Understanding the Fix

The patch adds a simple but effective check:

```javascript
// Before (vulnerable)
for (let i = 1; i < path.length; i++) {
  value = value[path[i]];
}

// After (patched)
for (let i = 1; i < path.length; i++) {
  if (!Object.prototype.hasOwnProperty.call(value, path[i])) {
    return waitForReference(response, ...);
  }
  value = value[path[i]];
}
```

### Why This Works

`hasOwnProperty` checks if a property exists **directly on the object**, not inherited from the prototype chain.

```javascript
const obj = { name: "test" };

obj.hasOwnProperty("name");      // true - exists on obj
obj.hasOwnProperty("__proto__"); // false - inherited
obj.hasOwnProperty("toString");  // false - inherited
```

By rejecting properties that don't exist directly on the object, the patch prevents prototype chain traversal.

---

## Knowledge Check

1. **Why can't WAF rules alone protect against this vulnerability?**
   <details>
   <summary>Answer</summary>
   The payload can be obfuscated in many ways (encoding, splitting across fields, using alternative JavaScript syntax). WAF rules can be bypassed, while patching fixes the root cause.
   </details>

2. **What does `--disable-proto=delete` do?**
   <details>
   <summary>Answer</summary>
   It removes the `__proto__` accessor from objects, preventing direct prototype access through that property. This is a defense-in-depth measure.
   </details>

3. **Why monitor for child process spawning?**
   <details>
   <summary>Answer</summary>
   The RCE payload uses `child_process.execSync()` to run commands. Web servers normally don't spawn child processes, so this activity is a strong indicator of exploitation.
   </details>

4. **What's the significance of npm's retroactive patching?**
   <details>
   <summary>Answer</summary>
   It means npm can replace published package contents without changing version numbers. This has security implications (good for emergency patches, but raises questions about package integrity).
   </details>

---

## Lab Exercise: Defense Testing

Test your defenses in the lab:

```bash
# 1. Try exploiting the patched container
python cli/react2shell.py http://localhost:3012 -c "id"
# Should fail/timeout

# 2. Try exploiting through WAF
python cli/react2shell.py http://localhost:3013 -c "id"
# Should be blocked

# 3. Check what the WAF logs show
docker logs react2shell-waf

# 4. Compare vulnerable vs patched behavior
docker logs react2shell-vulnerable
docker logs react2shell-patched
```

---

## Key Takeaways

1. **Patch immediately** - No workaround is as effective
2. **Defense in depth** - WAF + monitoring + isolation
3. **Monitor actively** - Know what normal looks like
4. **Prepare for incidents** - Have a response plan
5. **Understand the fix** - `hasOwnProperty` prevents prototype traversal

---

## Further Resources

### Official Advisories
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Vercel Changelog](https://vercel.com/changelog/cve-2025-55182)

### Technical Analysis
- [Wiz Blog - React2Shell](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)

### Tools
- [React2Shell CLI](../cli/) - For testing your defenses
- [Nuclei Template](../nuclei/) - For scanning

---

**Congratulations!** You've completed the CVE-2025-55182 learning path.

[← Back to Index](README.md)
