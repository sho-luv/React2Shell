/**
 * Vulnerable server for CVE-2025-55182 demonstration
 *
 * This server directly uses react-server-dom-webpack/server's decodeReplyFromBusboy
 * which is vulnerable to prototype pollution -> RCE.
 *
 * The --conditions react-server flag is required for the server module.
 */

import express from 'express';
import Busboy from 'busboy';

// Import the VULNERABLE server decoder
import serverPkg from 'react-server-dom-webpack/server';
const { decodeReplyFromBusboy } = serverPkg;

const app = express();
const PORT = process.env.PORT || 3000;

// Global error handlers
process.on('uncaughtException', (error) => {
  console.log('[GLOBAL] Uncaught Exception:', error.message);
  if (error.digest) {
    console.log('[GLOBAL] Error digest:', error.digest);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.log('[GLOBAL] Unhandled Rejection:', reason);
});

// Serve a simple HTML page
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>React Router RSC Lab - CVE-2025-55182</title>
  <style>
    body {
      font-family: -apple-system, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      margin: 0;
      padding: 2rem;
      color: #fff;
    }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { color: #ff4757; }
    .alert {
      background: rgba(255, 71, 87, 0.2);
      border: 1px solid #ff4757;
      padding: 1rem;
      border-radius: 8px;
      margin: 1rem 0;
    }
    .success {
      background: rgba(46, 213, 115, 0.2);
      border: 1px solid #2ed573;
    }
    pre {
      background: #0d1117;
      padding: 1rem;
      border-radius: 6px;
      color: #7ee787;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>React Router RSC Lab</h1>
    <p style="color: #ff4757; font-weight: bold;">
      VULNERABLE - react-server-dom-webpack 19.2.0
    </p>

    <div class="alert success">
      <p><strong>CVE-2025-55182 Confirmed Exploitable!</strong></p>
      <p>This server uses decodeReplyFromBusboy which is vulnerable to prototype pollution RCE.</p>
    </div>

    <div class="alert">
      <h3>Attack Info</h3>
      <pre>Package: react-server-dom-webpack@19.2.0
Function: decodeReplyFromBusboy

Endpoints:
  POST /_rsc
  POST /rsc
  POST /__rsc

Flag: /app/flag.txt

Test:
  python react2shell.py http://localhost:3015 -F react-router -c "id"</pre>
    </div>
  </div>
</body>
</html>
  `);
});

/**
 * VULNERABLE ENDPOINT - CVE-2025-55182
 */
app.post('/_rsc', async (req, res) => {
  console.log('[VULNERABLE] Processing Flight payload at /_rsc');
  console.log('[VULNERABLE] Content-Type:', req.headers['content-type']);

  try {
    const busboy = Busboy({ headers: req.headers });
    const reply = decodeReplyFromBusboy(busboy, {}, {});

    // Pipe request to busboy
    req.pipe(busboy);

    // Await the reply - this triggers the vulnerable code path
    const result = await reply;
    console.log('[VULNERABLE] Decoded result:', result);
    res.json({ success: true, result });
  } catch (error) {
    console.log('[VULNERABLE] Error:', error.message);
    console.log('[VULNERABLE] Digest:', error.digest);

    // Handle redirect (exploit exfiltration) - mimic Next.js behavior
    if (error.digest?.includes('REDIRECT')) {
      const match = error.digest.match(/REDIRECT;push;([^;]+);/);
      if (match) {
        console.log('[VULNERABLE] *** EXPLOIT TRIGGERED! Setting X-Action-Redirect...');
        // Next.js uses X-Action-Redirect header to communicate redirect URLs
        res.set('X-Action-Redirect', match[1]);
        res.status(303).json({ redirect: match[1] });
        return;
      }
    }

    res.status(500).json({ error: error.message, digest: error.digest });
  }
});

// Helper for processing RSC requests
async function handleRSCRequest(req, res) {
  try {
    const busboy = Busboy({ headers: req.headers });
    const reply = decodeReplyFromBusboy(busboy, {}, {});
    req.pipe(busboy);
    const result = await reply;
    res.json({ success: true, result });
  } catch (error) {
    if (error.digest?.includes('REDIRECT')) {
      const match = error.digest.match(/REDIRECT;push;([^;]+);/);
      if (match) {
        res.set('X-Action-Redirect', match[1]);
        res.status(303).json({ redirect: match[1] });
        return;
      }
    }
    res.status(500).json({ error: error.message });
  }
}

// Aliases
app.post('/rsc', async (req, res) => {
  console.log('[VULNERABLE] Alias /rsc');
  await handleRSCRequest(req, res);
});

app.post('/__rsc', async (req, res) => {
  console.log('[VULNERABLE] Alias /__rsc');
  await handleRSCRequest(req, res);
});

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  React Router RSC Lab - VULNERABLE TO CVE-2025-55182          ║
╠═══════════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${PORT}                      ║
║                                                               ║
║  Package: react-server-dom-webpack@19.2.0 (VULNERABLE)        ║
║  Function: decodeReplyFromBusboy                              ║
║                                                               ║
║  Endpoints:                                                   ║
║    POST /_rsc     - Flight protocol decoder                   ║
║    POST /rsc      - Alias                                     ║
║    POST /__rsc    - Alias                                     ║
║                                                               ║
║  Test:                                                        ║
║    python react2shell.py http://localhost:${PORT} -F react-router ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});
