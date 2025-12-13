import type { ReactNode } from 'react';

export default async function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html>
      <head>
        <title>Waku RSC Lab - CVE-2025-55182</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body style={{
        background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
        minHeight: '100vh',
        color: '#eee',
        margin: 0
      }}>
        {children}
      </body>
    </html>
  );
}

export const getConfig = async () => {
  return {
    render: 'static',
  };
};
