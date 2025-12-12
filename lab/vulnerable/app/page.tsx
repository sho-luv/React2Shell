import Link from 'next/link'
import { loginAction, healthCheck } from './actions'

export default async function Home() {
  const health = await healthCheck()

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
        <div className="alert alert-danger">
          This application is running vulnerable versions: Next.js {health.version} + React 19.2.0
          <br />
          <small>CVE-2025-55182 - Remote Code Execution via Prototype Pollution</small>
        </div>

        <div className="stats">
          <div className="stat">
            <div className="stat-value">1,247</div>
            <div className="stat-label">Active Users</div>
          </div>
          <div className="stat">
            <div className="stat-value">$84.2K</div>
            <div className="stat-label">Revenue</div>
          </div>
          <div className="stat">
            <div className="stat-value">99.9%</div>
            <div className="stat-label">Uptime</div>
          </div>
          <div className="stat">
            <div className="stat-value">3</div>
            <div className="stat-label">CTF Flags</div>
          </div>
        </div>

        <div className="grid">
          <div className="card">
            <h2>Login</h2>
            <form action={loginAction}>
              <input type="text" name="username" placeholder="Username" className="input" />
              <input type="password" name="password" placeholder="Password" className="input" />
              <button type="submit" className="btn">Sign In</button>
            </form>
          </div>

          <div className="card">
            <h2>System Info</h2>
            <pre>{JSON.stringify(health, null, 2)}</pre>
          </div>

          <div className="card">
            <h2>CTF Challenge</h2>
            <p style={{color: '#888', marginBottom: '1rem'}}>
              Find the hidden flags:
            </p>
            <ul style={{color: '#888', marginLeft: '1.5rem'}}>
              <li>Flag 1: Environment variables</li>
              <li>Flag 2: /root/flag.txt</li>
              <li>Flag 3: /app/secret/flag.txt</li>
            </ul>
          </div>

          <div className="card">
            <h2>Quick Actions</h2>
            <div style={{display: 'flex', gap: '0.5rem', flexWrap: 'wrap'}}>
              <Link href="/dashboard"><button className="btn">Dashboard</button></Link>
              <Link href="/admin"><button className="btn btn-danger">Admin Panel</button></Link>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
