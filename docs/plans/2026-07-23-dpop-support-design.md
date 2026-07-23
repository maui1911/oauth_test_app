# Design: DPoP support (RFC 9449) with on/off toggle

Date: 2026-07-23
Status: Approved

## Goal

Add DPoP (Demonstrating Proof of Possession, RFC 9449) to the OAuth test app, toggleable
with a checkbox in the OAuth Settings. When enabled, the app must behave as a realistic
DPoP client end-to-end: sender-constrained access tokens at the token endpoint AND
DPoP-authenticated calls to protected resources / connectors, including DPoP-Nonce handling.

## Requirements (confirmed)

- **Scope:** full end-to-end — DPoP proof on the token request AND on every resource call
  (`Get Protected Resource` + API Connectors).
- **Nonce:** full `DPoP-Nonce` challenge handling (RFC 9449 §8/9) with automatic retry.
- **UI:** checkbox "Enable DPoP" in the OAuth Settings block, persisted in localStorage,
  plus a status indicator showing whether the current token is DPoP or Bearer.
- **Key:** ES256 (EC P-256) keypair via WebCrypto, persisted (JWK in localStorage) so a
  stored access token still matches its key after a page reload.
- **Applies to:** both token flows (authorization_code + client_credentials) and both
  resource paths (protected resource + connectors).

## Architecture decision

The app uses a backend proxy (`server/server.cjs`) for token exchange (`/api/oauth/token`)
and resource access (`/api/proxy`). The DPoP **proof is generated in the frontend** (so it
carries the real `htu`/`htm` of the target URL and the private key never leaves the browser),
and the backend **forwards** it as the `DPoP` header and returns any `DPoP-Nonce` back to the
frontend.

Rejected alternatives:
- Inline DPoP logic in `oauthService` — mixes key management with flow logic, hard to share
  with `PerformanceService`.
- Generating the proof in the backend — private key would live on the server, not
  representative of a real browser client.

## Components

### 1. New `src/services/dpopService.ts`
- Generate an ES256 (EC P-256) keypair via `crypto.subtle.generateKey`, `extractable`,
  persisted as public + private JWK in `localStorage` under `dpop_keypair`.
- `createProof({ htu, htm, nonce?, accessToken? })` → signed DPoP proof JWT:
  - header: `{ typ: "dpop+jwt", alg: "ES256", jwk: <public JWK> }`
  - payload: `{ jti, htm, htu, iat, nonce?, ath? }`
  - `ath` = base64url(SHA-256(access_token)) for resource calls.
  - `htu` stripped of query/fragment.
  - ECDSA WebCrypto output is raw r‖s = JOSE format (no DER conversion).
- `jwkThumbprint()` (RFC 7638) for the `jkt` display and `dpop_jkt` auth param.
- `reset()` to force a new key.

### 2. `src/config/oauth.ts`
- Add `dpopEnabled: boolean` to `OAuthSettings` (default `false`).

### 3. `src/components/OAuthSettings.tsx`
- Checkbox "Enable DPoP (RFC 9449)" in both the display and edit views.

### 4. `src/services/oauthService.ts`
- Token requests (`exchangeCodeForTokens`, `getClientCredentialsToken`,
  `refreshAccessToken`): when DPoP is on, generate a proof (`htu`=token URL, `htm`=POST) and
  send it to `/api/oauth/token`. On a `use_dpop_nonce` response, capture the nonce, rebuild
  the proof with the nonce, and retry once. Persist `token_type`.
- Authorization URL: include `dpop_jkt=<thumbprint>` when DPoP is on.
- New central method `fetchResource(url, method)`: builds `Authorization: DPoP <token>` +
  `DPoP: <proof>` (with `ath`), calls `/api/proxy`, and retries once on 401 + `DPoP-Nonce`.
  With DPoP off it uses plain `Bearer`. Both `getProtectedResource()` and
  `PerformanceService.testConnector()` use this method (DRY).
- `refreshAccessToken` is routed through the proxy (needed for DPoP + fixes a pre-existing
  CORS problem).

### 5. `server/server.cjs`
- `/api/oauth/token`: accept `dpopProof` → set outgoing `DPoP` header; read `DPoP-Nonce` from
  the AS response and return it in the JSON (including on errors). Add `refresh_token` grant.
- `/api/proxy`: accept `dpopProof` + `method` → set outgoing `DPoP` header; the `DPoP-Nonce`
  response header is already forwarded to the frontend.

### 6. `src/App.tsx`
- Status label near the access token: "Token type: DPoP" vs "Bearer", plus the `jkt`
  thumbprint when DPoP is active.

## Error handling
- Nonce retry limited to once per request.
- Missing key → auto-generate.
- DPoP off behaves exactly as today (Bearer).

## Testing
- Manual testing against the real authorization server.
- `npm run build` / `npm run lint` for verification.
