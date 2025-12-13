'use client';

import { useState } from 'react';

export function Counter() {
  const [count, setCount] = useState(0);

  return (
    <div style={{
      background: 'rgba(255,255,255,0.05)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '8px',
      padding: '1rem',
      margin: '1rem 0'
    }}>
      <h2 style={{ color: '#00d4ff' }}>Counter Component</h2>
      <p>Count: {count}</p>
      <button
        onClick={() => setCount(c => c + 1)}
        style={{
          background: '#00d4ff',
          color: '#1a1a2e',
          border: 'none',
          padding: '0.5rem 1rem',
          borderRadius: '4px',
          cursor: 'pointer',
          marginRight: '0.5rem'
        }}
      >
        Increment
      </button>
      <button
        onClick={() => setCount(0)}
        style={{
          background: '#ff4757',
          color: 'white',
          border: 'none',
          padding: '0.5rem 1rem',
          borderRadius: '4px',
          cursor: 'pointer'
        }}
      >
        Reset
      </button>
    </div>
  );
}
