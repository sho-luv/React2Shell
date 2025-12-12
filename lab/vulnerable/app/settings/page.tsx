import Link from 'next/link'
import { updateSettings } from '../actions'

export default function Settings() {
  return (
    <>
      <header className="header">
        <div className="logo">SecureCorp</div>
        <nav className="nav">
          <Link href="/">Home</Link>
          <Link href="/dashboard">Dashboard</Link>
          <Link href="/admin">Admin</Link>
          <Link href="/api-keys">API Keys</Link>
          <Link href="/settings">Settings</Link>
        </nav>
        <span className="version-badge">VULNERABLE</span>
      </header>

      <div className="container">
        <h1 style={{marginBottom: '2rem'}}>Settings</h1>

        <div className="grid">
          <div className="card">
            <h2>Application Settings</h2>
            <form action={updateSettings}>
              <label style={{color: '#888', display: 'block', marginBottom: '0.5rem'}}>Site Name</label>
              <input type="text" name="siteName" defaultValue="SecureCorp" className="input" />

              <label style={{color: '#888', display: 'block', marginBottom: '0.5rem'}}>Contact Email</label>
              <input type="email" name="email" defaultValue="admin@securecorp.local" className="input" />

              <label style={{color: '#888', display: 'block', marginBottom: '0.5rem'}}>Timezone</label>
              <select name="timezone" className="input">
                <option value="UTC">UTC</option>
                <option value="EST">EST</option>
                <option value="PST">PST</option>
              </select>

              <button type="submit" className="btn">Save Settings</button>
            </form>
          </div>

          <div className="card">
            <h2>Security Settings</h2>
            <form action={updateSettings}>
              <label style={{display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem'}}>
                <input type="checkbox" name="2fa" />
                <span>Enable 2FA</span>
              </label>
              <label style={{display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem'}}>
                <input type="checkbox" name="audit" defaultChecked />
                <span>Enable Audit Logging</span>
              </label>
              <label style={{display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem'}}>
                <input type="checkbox" name="waf" />
                <span>Enable WAF (broken)</span>
              </label>
              <button type="submit" className="btn">Update Security</button>
            </form>
          </div>

          <div className="card">
            <h2>Vulnerability Info</h2>
            <pre>{`CVE: CVE-2025-55182
CVSS: 10.0 (Critical)
Type: Prototype Pollution RCE

Affected:
- React 19.0.0 - 19.2.0
- Next.js 14.3+ / 15.x / 16.x

This instance: VULNERABLE
React: 19.2.0
Next.js: 15.4.0`}</pre>
          </div>
        </div>
      </div>
    </>
  )
}
