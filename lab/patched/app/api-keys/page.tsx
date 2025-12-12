import Link from 'next/link'
import { generateApiKey } from '../actions'

export default function ApiKeys() {
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
        <h1 style={{marginBottom: '2rem'}}>API Key Management</h1>

        <div className="grid">
          <div className="card">
            <h2>Generate New API Key</h2>
            <form action={generateApiKey}>
              <input type="text" name="name" placeholder="Key name (e.g., Production)" className="input" />
              <select name="permissions" className="input">
                <option value="read">Read Only</option>
                <option value="write">Read/Write</option>
                <option value="admin">Full Access</option>
              </select>
              <button type="submit" className="btn">Generate Key</button>
            </form>
          </div>

          <div className="card">
            <h2>Active Keys</h2>
            <table>
              <thead>
                <tr><th>Name</th><th>Key</th><th>Created</th></tr>
              </thead>
              <tbody>
                <tr><td>Production</td><td>ak_prod_****</td><td>2025-01-15</td></tr>
                <tr><td>Development</td><td>ak_dev_****</td><td>2025-02-20</td></tr>
                <tr><td>Testing</td><td>ak_test_****</td><td>2025-03-10</td></tr>
              </tbody>
            </table>
          </div>

          <div className="card">
            <h2>API Endpoints</h2>
            <pre>{`POST /api/users
GET  /api/users/:id
POST /api/keys/generate
POST /api/export

All endpoints vulnerable to
CVE-2025-55182 RCE`}</pre>
          </div>
        </div>
      </div>
    </>
  )
}
