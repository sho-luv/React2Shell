import Link from 'next/link'
import { adminAction, getUserData } from '../actions'

export default async function Admin() {
  const users = [
    await getUserData(1),
    await getUserData(2),
    await getUserData(3),
  ].filter(Boolean)

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
        <h1 style={{marginBottom: '2rem'}}>Admin Panel</h1>

        <div className="alert alert-warning">
          Admin actions are processed via Server Actions - vulnerable to prototype pollution RCE
        </div>

        <div className="grid">
          <div className="card card-wide">
            <h2>User Management</h2>
            <table>
              <thead>
                <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
              </thead>
              <tbody>
                {users.map((user: any) => (
                  <tr key={user.id}>
                    <td>{user.id}</td>
                    <td>{user.username}</td>
                    <td>{user.email}</td>
                    <td>{user.role}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card">
            <h2>Admin Actions</h2>
            <form action={adminAction}>
              <select name="action" className="input">
                <option value="restart">Restart Service</option>
                <option value="clear_cache">Clear Cache</option>
                <option value="backup">Create Backup</option>
                <option value="rotate_keys">Rotate API Keys</option>
              </select>
              <button type="submit" className="btn btn-danger">Execute</button>
            </form>
          </div>

          <div className="card">
            <h2>System Secrets</h2>
            <p style={{color: '#888', marginBottom: '1rem'}}>
              Sensitive configuration (check .env file)
            </p>
            <pre>{`DATABASE_URL=*****
AWS_ACCESS_KEY=*****
STRIPE_KEY=*****
JWT_SECRET=*****

Hint: Use RCE to read these!
Command: cat /app/.env`}</pre>
          </div>

          <div className="card">
            <h2>Server Info</h2>
            <pre>{`Platform: linux
Node: v20.x
Next.js: 15.4.0 (VULNERABLE)
React: 19.2.0 (VULNERABLE)

Flag location hint:
/root/flag.txt`}</pre>
          </div>
        </div>
      </div>
    </>
  )
}
