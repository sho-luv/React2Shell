import Link from 'next/link'
import { getUserData, exportData } from '../actions'

export default async function Dashboard() {
  const user = await getUserData(1)

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
        <h1 style={{marginBottom: '2rem'}}>Dashboard</h1>

        <div className="grid">
          <div className="card">
            <h2>User Profile</h2>
            {user && (
              <table>
                <tbody>
                  <tr><th>ID</th><td>{user.id}</td></tr>
                  <tr><th>Username</th><td>{user.username}</td></tr>
                  <tr><th>Email</th><td>{user.email}</td></tr>
                  <tr><th>Role</th><td>{user.role}</td></tr>
                  <tr><th>API Key</th><td>{user.apiKey}</td></tr>
                </tbody>
              </table>
            )}
          </div>

          <div className="card">
            <h2>Recent Activity</h2>
            <table>
              <thead>
                <tr><th>Time</th><th>Action</th><th>Status</th></tr>
              </thead>
              <tbody>
                <tr><td>10:32 AM</td><td>Login</td><td style={{color:'#7ee787'}}>Success</td></tr>
                <tr><td>10:15 AM</td><td>API Call</td><td style={{color:'#7ee787'}}>Success</td></tr>
                <tr><td>09:45 AM</td><td>Export Data</td><td style={{color:'#7ee787'}}>Success</td></tr>
                <tr><td>09:30 AM</td><td>Failed Login</td><td style={{color:'#ff4757'}}>Failed</td></tr>
              </tbody>
            </table>
          </div>

          <div className="card">
            <h2>Export Data</h2>
            <p style={{color: '#888', marginBottom: '1rem'}}>Export user data in various formats</p>
            <form action={exportData}>
              <select name="format" className="input">
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
                <option value="xml">XML</option>
              </select>
              <button type="submit" className="btn">Export</button>
            </form>
          </div>

          <div className="card">
            <h2>Server Endpoints</h2>
            <pre>{`Available actions:
- /dashboard (this page)
- /admin (admin panel)
- /api-keys (manage keys)
- /settings (configuration)

All endpoints use Server Actions
vulnerable to CVE-2025-55182`}</pre>
          </div>
        </div>
      </div>
    </>
  )
}
