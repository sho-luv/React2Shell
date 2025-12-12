'use server'

// Simulated user database
const users = [
  { id: 1, username: 'admin', email: 'admin@securecorp.local', role: 'admin', apiKey: 'ak_admin_xxxxx' },
  { id: 2, username: 'john.doe', email: 'john@securecorp.local', role: 'user', apiKey: 'ak_user_12345' },
  { id: 3, username: 'jane.smith', email: 'jane@securecorp.local', role: 'user', apiKey: 'ak_user_67890' },
]

// Action: Login (vulnerable to exploit)
export async function loginAction(formData: FormData): Promise<void> {
  const username = formData.get('username')
  const password = formData.get('password')
  console.log(`[AUTH] Login attempt: ${username}`)
}

// Action: Get user data
export async function getUserData(userId: number) {
  console.log(`[API] Fetching user: ${userId}`)
  return users.find(u => u.id === userId) || null
}

// Action: Admin function
export async function adminAction(formData: FormData): Promise<void> {
  const action = formData.get('action')
  console.log(`[ADMIN] Action: ${action}`)
}

// Action: API key generation
export async function generateApiKey(formData: FormData): Promise<void> {
  const name = formData.get('name')
  console.log(`[API] Generating key for: ${name}`)
}

// Action: Export data
export async function exportData(formData: FormData): Promise<void> {
  const format = formData.get('format')
  console.log(`[EXPORT] Format: ${format}`)
}

// Action: System health check
export async function healthCheck() {
  return {
    status: 'healthy',
    version: '15.4.0',
    uptime: process.uptime(),
    env: process.env.NODE_ENV
  }
}

// Action: Process payment (fake)
export async function processPayment(formData: FormData): Promise<void> {
  const amount = formData.get('amount')
  console.log(`[PAYMENT] Processing: $${amount}`)
}

// Action: Update settings
export async function updateSettings(formData: FormData): Promise<void> {
  const settings = Object.fromEntries(formData.entries())
  console.log(`[SETTINGS] Update:`, settings)
}
