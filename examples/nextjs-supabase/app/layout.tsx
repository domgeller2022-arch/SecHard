import type { ReactNode } from 'react';

export const metadata = { title: 'Private notes (reference application)' };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: 'system-ui, sans-serif', margin: '2rem auto', maxWidth: '40rem', padding: '0 1rem' }}>
        <h1 style={{ fontSize: '1.25rem' }}>Private notes</h1>
        <p style={{ color: '#555', fontSize: '0.9rem' }}>
          Reference application for the hardening repository. Local development only.
        </p>
        {children}
      </body>
    </html>
  );
}
