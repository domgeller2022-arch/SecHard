import type { NextConfig } from 'next';

// Deliberately minimal. The interesting configuration for this application is the session handling
// in middleware.ts and the authorization at the data boundary, not the framework's options.
//
// `productionBrowserSourceMaps` is left at its default (off), which is what SEC-02's build check
// inspects: a browser bundle that ships readable source is a finding, and a private application has
// no reason to serve one.
const config: NextConfig = {
  reactStrictMode: true,
  typescript: { ignoreBuildErrors: false },
};

export default config;
