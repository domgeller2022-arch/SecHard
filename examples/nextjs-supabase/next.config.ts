import type { NextConfig } from 'next';

// Deliberately minimal. The interesting configuration for this application is the session handling
// in middleware.ts and the authorization at the data boundary, not the framework's options.
//
// `productionBrowserSourceMaps` is left at its default (off), which is what SEC-02's build check
// inspects: a browser bundle that ships readable source is a finding, and a private application has
// no reason to serve one.
// Route-appropriate response headers, asserted by the live HTTP recipe in the hardening repository.
//
// These are the headers every response here should carry. HSTS is deliberately absent: it is only
// meaningful over HTTPS, and sending it from a plain-HTTP local server would be a claim about
// transport security that this environment cannot make. The production transport requirement is a
// separate check, which correctly blocks while no TLS evidence exists.
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

const config: NextConfig = {
  reactStrictMode: true,
  typescript: { ignoreBuildErrors: false },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default config;
