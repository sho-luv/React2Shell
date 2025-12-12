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
        <span className="version-badge" style={{backgroundColor: '#22c55e'}}>PATCHED</span>
      </header>

      <div className="container">
        <div className="alert" style={{backgroundColor: '#166534', borderColor: '#22c55e'}}>
          This application is running PATCHED versions: Next.js {health.version} + React 19.2.1
          <br />
          <small>CVE-2025-55182 has been fixed in this version</small>
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
          <div className="stat" style={{borderColor: '#22c55e'}}>
            <div className="stat-value" style={{color: '#22c55e'}}>SECURE</div>
            <div className="stat-label">Status</div>
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
            <h2>Security Status</h2>
            <p style={{color: '#22c55e', marginBottom: '1rem'}}>
              This instance is protected against CVE-2025-55182
            </p>
            <ul style={{color: '#888', marginLeft: '1.5rem'}}>
              <li>React: 19.2.1 (patched)</li>
              <li>Next.js: 15.4.8 (patched)</li>
              <li>RSC exploit: Blocked</li>
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
