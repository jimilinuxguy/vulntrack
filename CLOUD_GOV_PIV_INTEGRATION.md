# Cloud.gov PIV-Proxy integration assessment

## Current status
VulnTrack is hosted on Cloud.gov using the disposable SQLite demo configuration. PIV-Proxy is a separate local Docker Compose application with Nginx browser mTLS, Python certificate and CRL verification, Redis sessions, and an optional OIDC provider.

**Do not deploy PIV-Proxy as a public authentication service until Cloud.gov's ingress mTLS support has been verified.**

## Blocking platform requirement
Cloud Foundry documents operator-managed external-client mTLS domains, where Gorouter validates an external client certificate against a configured CA and forwards a sanitized X-Forwarded-Client-Cert header. This requires platform-operator configuration, and is not confirmed as available in Cloud.gov's sandbox-nasa org.

Ask Cloud.gov support:
- Can sandbox-nasa use an external-client mTLS domain for NASA PIV Authentication certificates?
- Can the platform validate the client certificate and forward the verified full certificate with a sanitized, non-spoofable header?
- Can a separate public HTTPS route expose PIV-Proxy OIDC discovery, authorization, token, and JWKS endpoints without requiring a client certificate?
- What revocation and network controls are available, and who provisions these routes?

Reference: https://docs.cloudfoundry.org/concepts/identity-aware-routing.html

## Required implementation work
1. Create a Cloud Foundry-specific PIV-Proxy deployment only after mTLS ingress is confirmed. Never trust user-supplied XFCC, X-PIV-Cert, or X-PIV-Verified headers.
2. Retain the Python certificate policy, issuer, EKU, expiration and fresh signed CRL checks.
3. Provide an approved durable Redis service, signing-key secret management, and CRL refresh; local Docker Compose resources do not automatically deploy to CF.
4. Register VulnTrack as an OIDC client with exact redirect URI https://vulntrack-sandbox.app.cloud.gov/.
5. Adapt VulnTrack's browser to perform the OIDC authorization-code/PKCE token exchange server-side (or configure safe CORS) and validate state and nonce.
6. Resolve token type mismatch: PIV-Proxy currently issues a signed ID token but an opaque access token. VulnTrack's APIs require a verifiable JWT. Prefer a purpose-specific, audience-bound JWT access token and enforce tenant authorization using explicit user membership or admin grants.
7. Test real NASA PIV authentication, invalid/revoked certificates, no-card requests, spoofed headers, cross-tenant access, and logout before declaring the integration operational.

## Deployment state
No public PIV-Proxy deployment has been performed. Do not use the local Docker endpoint as a public identity provider or disable authentication for the demo.
