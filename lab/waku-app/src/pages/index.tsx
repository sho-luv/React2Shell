import { Counter } from '../components/Counter';
import { GreetForm } from '../components/GreetForm';

// Server action for Waku
async function greetAction(formData: FormData) {
  'use server';
  const name = formData.get('name') as string;
  console.log(`[SERVER ACTION] Greeting: ${name}`);
  return { message: `Hello, ${name}!` };
}

export default async function HomePage() {
  return (
    <div style={{ padding: '2rem', fontFamily: 'system-ui' }}>
      <h1 style={{ color: '#00d4ff' }}>Waku RSC Lab</h1>
      <p style={{ color: '#ff4757' }}>VULNERABLE - Waku 0.27.1 + React 19.2.0</p>

      <div style={{
        background: 'rgba(255,71,87,0.2)',
        border: '1px solid #ff4757',
        borderRadius: '8px',
        padding: '1rem',
        margin: '1rem 0'
      }}>
        <p>This Waku instance is vulnerable to CVE-2025-55182</p>
        <p>RSC endpoints: /RSC/, /__RSC__/</p>
      </div>

      <div style={{
        background: 'rgba(255,255,255,0.05)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '8px',
        padding: '1rem',
        margin: '1rem 0'
      }}>
        <h2 style={{ color: '#00d4ff' }}>Server Action Test</h2>
        <GreetForm action={greetAction} />
      </div>

      <Counter />

      <div style={{ marginTop: '2rem', color: '#888' }}>
        <p>Flag location: /app/flag.txt</p>
      </div>
    </div>
  );
}
