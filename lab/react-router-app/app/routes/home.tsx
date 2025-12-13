import { Form } from "react-router";

// Server action using "use server" directive - this is what makes it vulnerable
// The server action uses React's Flight protocol for serialization
async function greetAction(formData: FormData): Promise<{ message: string }> {
  "use server";
  const name = formData.get("name") as string;
  console.log(`[SERVER ACTION] Greeting: ${name}`);
  return { message: `Hello, ${name}!` };
}

// Another server action to demonstrate the vulnerability surface
async function processData(formData: FormData): Promise<{ result: string }> {
  "use server";
  const data = formData.get("data") as string;
  console.log(`[SERVER ACTION] Processing: ${data}`);
  return { result: `Processed: ${data}` };
}

export default function Home() {
  return (
    <div>
      <h1>React Router RSC Lab</h1>
      <p style={{ color: '#ff4757', fontWeight: 'bold' }}>
        VULNERABLE - React Router 7.5.0 + React 19.2.0 + react-server-dom-webpack 19.2.0
      </p>

      <div className="alert">
        <p>This React Router instance uses react-server-dom-webpack for RSC</p>
        <p>Vulnerable to CVE-2025-55182 via Flight protocol deserialization</p>
      </div>

      <div className="card">
        <h2 style={{ color: '#00d4ff' }}>Server Action Test</h2>
        <Form action={greetAction}>
          <input
            type="text"
            name="name"
            placeholder="Enter name"
            style={{
              background: 'rgba(255,255,255,0.1)',
              border: '1px solid rgba(255,255,255,0.2)',
              padding: '0.75rem',
              borderRadius: '6px',
              color: '#fff',
              marginRight: '0.5rem'
            }}
          />
          <button type="submit" className="btn">
            Greet (Server Action)
          </button>
        </Form>
      </div>

      <div className="card">
        <h2 style={{ color: '#00d4ff' }}>Attack Info</h2>
        <pre style={{
          background: '#0d1117',
          padding: '1rem',
          borderRadius: '6px',
          color: '#7ee787'
        }}>{`RSC Package: react-server-dom-webpack@19.2.0
Endpoints to test:
  /_rsc
  /rsc
  /__rsc
  /

Flag location: /app/flag.txt

Test with:
  python react2shell.py http://localhost:3015 -F react-router -c "id"`}</pre>
      </div>
    </div>
  );
}
