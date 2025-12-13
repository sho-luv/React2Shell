'use client';

import { useState } from 'react';

interface GreetFormProps {
  action: (formData: FormData) => Promise<{ message: string }>;
}

export function GreetForm({ action }: GreetFormProps) {
  const [result, setResult] = useState<string>('');

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const response = await action(formData);
    setResult(response.message);
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          name="name"
          placeholder="Enter name"
          style={{
            background: 'rgba(255,255,255,0.1)',
            border: '1px solid rgba(255,255,255,0.2)',
            padding: '0.5rem',
            borderRadius: '4px',
            color: '#fff',
            marginRight: '0.5rem'
          }}
        />
        <button
          type="submit"
          style={{
            background: '#00d4ff',
            color: '#1a1a2e',
            border: 'none',
            padding: '0.5rem 1rem',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Greet (Server Action)
        </button>
      </form>
      {result && (
        <p style={{ marginTop: '0.5rem', color: '#7ee787' }}>{result}</p>
      )}
    </div>
  );
}
