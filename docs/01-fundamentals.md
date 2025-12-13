# Chapter 1: Fundamentals

Before diving into CVE-2025-55182, you need to understand the underlying technologies. This chapter covers the building blocks.

---

## What are React Server Components?

React Server Components (RSC) allow React components to run on the server instead of the browser. This enables:

- **Server-side data fetching** - Components can directly query databases
- **Reduced client bundle size** - Server code never ships to the browser
- **Improved performance** - Less JavaScript for the client to parse

### Traditional React (Client-Side)

```
Browser Request → Server sends HTML + JavaScript → Browser runs React
```

Everything happens in the browser. The server just serves static files.

### React Server Components

```
Browser Request → Server runs React → Server sends rendered output → Browser displays
```

The server executes React code and sends the result to the browser.

---

## The Flight Protocol

RSC uses a serialization format called "Flight" to send data from server to client. Think of it as JSON, but designed for React component trees.

### Basic Flight Format

```
0:["$","div",null,{"children":"Hello World"}]
1:{"name":"John","age":30}
2:["$","span",null,{"children":"$1"}]
```

Each line is: `ID:DATA`

### Special Prefixes

Flight uses prefixes to represent special values:

| Prefix | Meaning | Example |
|--------|---------|---------|
| `$` | React element | `["$","div",null,{}]` |
| `$L` | Lazy component | `$L1` (lazy load chunk 1) |
| `$@` | Raw reference | `$@0` (raw access to chunk 0) |
| `$B` | Blob/Binary | `$B1337` |

### Why This Matters

The Flight protocol needs to serialize complex objects, including **references between chunks**. This reference system is where the vulnerability lives.

---

## Prototype Pollution Basics

JavaScript objects inherit properties from their prototype chain.

### Normal Property Access

```javascript
const obj = { name: "Alice" };
console.log(obj.name);        // "Alice"
console.log(obj.toString);    // [Function: toString] - inherited from Object.prototype
```

### The Prototype Chain

```
obj → Object.prototype → null
```

When you access `obj.toString`, JavaScript:
1. Looks for `toString` on `obj` - not found
2. Looks for `toString` on `Object.prototype` - found!

### Pollution Attack

If an attacker can modify `Object.prototype`, ALL objects are affected:

```javascript
// Attacker pollutes the prototype
Object.prototype.isAdmin = true;

// Later, innocent code checks:
const user = { name: "Bob" };
if (user.isAdmin) {
  // This is now TRUE for every object!
  grantAdminAccess();
}
```

### The `__proto__` Property

Every object has a hidden `__proto__` property pointing to its prototype:

```javascript
const obj = {};
obj.__proto__ === Object.prototype  // true

// This pollutes Object.prototype:
obj.__proto__.polluted = true;

// Now every object has this property:
const newObj = {};
console.log(newObj.polluted);  // true
```

---

## Server Actions in Next.js

Next.js uses "Server Actions" - functions that run on the server but can be called from the client.

### Defining a Server Action

```javascript
// app/actions.js
'use server'

export async function submitForm(formData) {
  // This code runs on the SERVER
  const name = formData.get('name');
  await database.insert({ name });
  return { success: true };
}
```

### Calling from Client

```javascript
// app/page.js
import { submitForm } from './actions';

export default function Page() {
  return (
    <form action={submitForm}>
      <input name="name" />
      <button type="submit">Submit</button>
    </form>
  );
}
```

### What Happens Under the Hood

1. Client sends POST request with form data
2. Request includes `Next-Action` header identifying the function
3. Server deserializes the data using Flight protocol
4. Server executes the action
5. Server sends response back

**The vulnerability is in step 3** - the deserialization.

---

## Knowledge Check

Before continuing, make sure you understand:

1. **What's the difference between RSC and traditional React?**
   <details>
   <summary>Answer</summary>
   RSC runs React components on the server, sending rendered output to the client. Traditional React runs entirely in the browser.
   </details>

2. **What is the Flight protocol used for?**
   <details>
   <summary>Answer</summary>
   Flight serializes React component trees and data for transmission between server and client. It's like JSON but designed for React.
   </details>

3. **How does prototype pollution work?**
   <details>
   <summary>Answer</summary>
   By modifying Object.prototype (via __proto__ or other means), an attacker can add properties that appear on ALL objects in the application.
   </details>

4. **Where does deserialization happen in Server Actions?**
   <details>
   <summary>Answer</summary>
   On the server, when processing the incoming request. The server deserializes the Flight-encoded data before executing the action.
   </details>

---

## Lab Exercise

Start the lab environment and explore:

```bash
cd lab
docker-compose up -d
```

1. Visit http://localhost:3011 and view page source
2. Look for `__next_f` or `self.__next_f` markers
3. Open Network tab, look for requests with `RSC: 1` header
4. Notice the Flight-formatted responses

---

**Next Chapter:** [The Vulnerability →](02-vulnerability.md)
