# DPoP Support (RFC 9449) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add toggleable DPoP (RFC 9449) support to the OAuth test app — sender-constrained tokens at the token endpoint and DPoP-authenticated resource calls, with full DPoP-Nonce handling, switchable via a checkbox in OAuth Settings.

**Architecture:** The DPoP proof is generated in the frontend (real `htu`/`htm`, private key never leaves the browser) by a new `DPoPService`. The Express proxy forwards the proof as the `DPoP` header and relays `DPoP-Nonce` back. A single `fetchResource()` method in `OAuthService` centralizes DPoP/Bearer logic for both the protected-resource button and the connectors.

**Tech Stack:** React + TypeScript + Vite (frontend), Express + axios (`server/server.cjs`), WebCrypto (ECDSA P-256 / ES256), localStorage.

**Note on testing:** This project has no unit-test harness (only `build` + `lint`). Each task is verified with `npm run build` (TypeScript typecheck via `tsc`) and `npm run lint`, plus a final manual browser verification. Adding a full test runner is intentionally out of scope (YAGNI).

**Commit convention:** existing repo has no strict style; use short `feat:`/`chore:` prefixes.

---

## Task 1: Add `dpopEnabled` to OAuth settings config

**Files:**
- Modify: `src/config/oauth.ts`

**Step 1: Add the field to the interface and default, and merge defaults on read**

Replace the whole file `src/config/oauth.ts` with:

```ts
export interface OAuthSettings {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  protectedResource: string;
  scope: string;
  dpopEnabled: boolean;
  endpoints: {
    authorize: string;
    token: string;
  };
}

const DEFAULT_SETTINGS: OAuthSettings = {
  baseUrl: "https://your-oauth-server.com",
  clientId: "your_client_id",
  clientSecret: "your_client_secret",
  redirectUri: "http://localhost:3000/callback",
  protectedResource: "https://your-oauth-server.com/api/resource",
  scope: "openid profile email",
  dpopEnabled: false,
  endpoints: {
    authorize: "/oauth/authorize",
    token: "/oauth/token",
  },
};

export function getOAuthSettings(): OAuthSettings {
  const storedSettings = localStorage.getItem("oauth_settings");
  if (storedSettings) {
    // Merge with defaults so newly added fields (e.g. dpopEnabled) get a value.
    return { ...DEFAULT_SETTINGS, ...JSON.parse(storedSettings) };
  }
  return DEFAULT_SETTINGS;
}

export const saveOAuthSettings = (settings: OAuthSettings) => {
  localStorage.setItem("oauth_settings", JSON.stringify(settings));
};

export const resetOAuthSettings = () => {
  localStorage.removeItem("oauth_settings");
};
```

**Step 2: Typecheck**

Run: `npm run build`
Expected: build succeeds (no TS errors). (There will be new usages later; this file compiles standalone.)

**Step 3: Commit**

```bash
git add src/config/oauth.ts
git commit -m "feat: add dpopEnabled to OAuth settings"
```

---

## Task 2: Create `DPoPService` (keypair + proof generation)

**Files:**
- Create: `src/services/dpopService.ts`

**Step 1: Write the service**

Create `src/services/dpopService.ts`:

```ts
// DPoP (RFC 9449) helper: ES256 (EC P-256) keypair management + proof-JWT generation.
// The private key never leaves the browser; the public JWK is embedded in each proof.

interface StoredKeyPair {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

const STORAGE_KEY = "dpop_keypair";

export class DPoPService {
  private static instance: DPoPService;
  private keyPairPromise: Promise<CryptoKeyPair> | null = null;
  private publicJwk: JsonWebKey | null = null;

  public static getInstance(): DPoPService {
    if (!DPoPService.instance) {
      DPoPService.instance = new DPoPService();
    }
    return DPoPService.instance;
  }

  private async loadOrCreateKeyPair(): Promise<CryptoKeyPair> {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const { publicJwk, privateJwk } = JSON.parse(stored) as StoredKeyPair;
        const publicKey = await crypto.subtle.importKey(
          "jwk",
          publicJwk,
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"]
        );
        const privateKey = await crypto.subtle.importKey(
          "jwk",
          privateJwk,
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign"]
        );
        this.publicJwk = publicJwk;
        return { publicKey, privateKey };
      } catch {
        // Corrupt/incompatible stored key — fall through and regenerate.
      }
    }

    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const rawPublicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    // Only the required members belong in the proof header's public JWK.
    const publicJwk: JsonWebKey = {
      kty: rawPublicJwk.kty,
      crv: rawPublicJwk.crv,
      x: rawPublicJwk.x,
      y: rawPublicJwk.y,
    };
    this.publicJwk = publicJwk;
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ publicJwk, privateJwk }));
    return keyPair;
  }

  private getKeyPair(): Promise<CryptoKeyPair> {
    if (!this.keyPairPromise) {
      this.keyPairPromise = this.loadOrCreateKeyPair();
    }
    return this.keyPairPromise;
  }

  public async getPublicJwk(): Promise<JsonWebKey> {
    await this.getKeyPair();
    return this.publicJwk!;
  }

  /** RFC 7638 JWK thumbprint (base64url SHA-256) — used for `jkt` display and `dpop_jkt`. */
  public async getThumbprint(): Promise<string> {
    const jwk = await this.getPublicJwk();
    // EC canonical members in lexicographic order: crv, kty, x, y.
    const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical)
    );
    return base64UrlEncode(new Uint8Array(digest));
  }

  public async createProof(opts: {
    htu: string;
    htm: string;
    nonce?: string;
    accessToken?: string;
  }): Promise<string> {
    const keyPair = await this.getKeyPair();
    const publicJwk = await this.getPublicJwk();

    const header = { typ: "dpop+jwt", alg: "ES256", jwk: publicJwk };

    const payload: Record<string, unknown> = {
      jti: generateJti(),
      htm: opts.htm.toUpperCase(),
      htu: normalizeHtu(opts.htu),
      iat: Math.floor(Date.now() / 1000),
    };
    if (opts.nonce) payload.nonce = opts.nonce;
    if (opts.accessToken) payload.ath = await accessTokenHash(opts.accessToken);

    const encodedHeader = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(header))
    );
    const encodedPayload = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(payload))
    );
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // WebCrypto ECDSA output is raw r||s (IEEE P1363) === JOSE format. No DER conversion.
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      new TextEncoder().encode(signingInput)
    );
    const encodedSignature = base64UrlEncode(new Uint8Array(signature));
    return `${signingInput}.${encodedSignature}`;
  }

  /** Forget the current key (a new one is generated on next use). */
  public reset(): void {
    localStorage.removeItem(STORAGE_KEY);
    this.keyPairPromise = null;
    this.publicJwk = null;
  }
}

function normalizeHtu(url: string): string {
  try {
    const u = new URL(url);
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return url;
  }
}

async function accessTokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  return base64UrlEncode(new Uint8Array(digest));
}

function generateJti(): string {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return base64UrlEncode(arr);
}

function base64UrlEncode(buffer: Uint8Array): string {
  let str = "";
  for (let i = 0; i < buffer.length; i++) {
    str += String.fromCharCode(buffer[i]);
  }
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
```

**Step 2: Typecheck**

Run: `npm run build`
Expected: build succeeds.

**Step 3: Browser smoke-check (manual, optional but recommended)**

With the dev server running, open the browser console at http://localhost:3000 and run:

```js
const { DPoPService } = await import('/src/services/dpopService.ts');
const p = await DPoPService.getInstance().createProof({ htu: 'https://x.test/token', htm: 'POST' });
console.log(p);
```
Expected: a three-part `xxx.yyy.zzz` string. Paste it into https://jwt.io and confirm the header has `typ: "dpop+jwt"`, `alg: "ES256"`, an embedded `jwk`, and the payload has `jti`, `htm`, `htu`, `iat`.

**Step 4: Commit**

```bash
git add src/services/dpopService.ts
git commit -m "feat: add DPoPService for ES256 keypair and proof generation"
```

---

## Task 3: Backend — forward DPoP + relay nonce on `/api/oauth/token` (+ refresh grant)

**Files:**
- Modify: `server/server.cjs` (the `/api/oauth/token` handler, lines ~16-40)

**Step 1: Replace the `/api/oauth/token` handler**

Replace the entire `app.post('/api/oauth/token', ...)` block with:

```js
// Proxy endpoint for OAuth token exchange
app.post('/api/oauth/token', async (req, res) => {
  console.log('Received /api/oauth/token request:', req.body);
  const {
    tokenUrl, clientId, clientSecret, code, redirectUri,
    codeVerifier, grantType, scope, refreshToken, dpopProof
  } = req.body;
  try {
    const params = new URLSearchParams();
    params.append('client_id', clientId);
    if (clientSecret) params.append('client_secret', clientSecret);
    params.append('grant_type', grantType);
    if (grantType === 'authorization_code') {
      params.append('code', code);
      params.append('redirect_uri', redirectUri);
      if (codeVerifier) params.append('code_verifier', codeVerifier);
    } else if (grantType === 'client_credentials') {
      if (scope) params.append('scope', scope);
    } else if (grantType === 'refresh_token') {
      params.append('refresh_token', refreshToken);
    }

    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (dpopProof) headers['DPoP'] = dpopProof;

    const response = await axios.post(tokenUrl, params, { headers });
    console.log('OAuth server response:', response.data);
    const nonce = response.headers['dpop-nonce'];
    if (nonce) res.set('DPoP-Nonce', nonce);
    res.json(response.data);
  } catch (error) {
    const nonce = error.response?.headers?.['dpop-nonce'];
    console.error('Error in /api/oauth/token:', error.response?.data || error.message);
    if (nonce) res.set('DPoP-Nonce', nonce);
    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error || error.message,
      details: error.response?.data,
      dpopNonce: nonce,
    });
  }
});
```

**Step 2: Restart the backend window** (Ctrl+C then `node server/server.cjs`) so changes load. Confirm it logs `OAuth proxy server running on port 8080`.

**Step 3: Commit**

```bash
git add server/server.cjs
git commit -m "feat: forward DPoP header and relay DPoP-Nonce on token endpoint"
```

---

## Task 4: Backend — forward DPoP + honor method on `/api/proxy`

**Files:**
- Modify: `server/server.cjs` (the `/api/proxy` handler)

**Step 1: Update the request construction**

In the `app.post('/api/proxy', ...)` handler, change the destructuring and the axios call.

Replace:
```js
  const { url } = req.body;
  const authHeader = req.headers['authorization'];
  console.log('Proxying connector call to:', url);
  try {
    const response = await axios.get(url, {
      headers: authHeader ? { Authorization: authHeader } : {},
      validateStatus: () => true, // Forward all responses
      responseType: 'json' // Ensure JSON response type
    });
```
With:
```js
  const { url, method, dpopProof } = req.body;
  const authHeader = req.headers['authorization'];
  console.log('Proxying connector call to:', url);
  try {
    const outgoingHeaders = {};
    if (authHeader) outgoingHeaders['Authorization'] = authHeader;
    if (dpopProof) outgoingHeaders['DPoP'] = dpopProof;
    const response = await axios({
      method: method || 'GET',
      url,
      headers: outgoingHeaders,
      validateStatus: () => true, // Forward all responses
      responseType: 'json' // Ensure JSON response type
    });
```

(The existing header-cleanup block does NOT strip `dpop-nonce`, so the RS nonce is already relayed to the frontend. Leave it as-is.)

**Step 2: Restart the backend window** and confirm it starts cleanly.

**Step 3: Commit**

```bash
git add server/server.cjs
git commit -m "feat: forward DPoP header and honor method on proxy endpoint"
```

---

## Task 5: `OAuthService` — DPoP on token requests, nonce retry, token_type, dpop_jkt

**Files:**
- Modify: `src/services/oauthService.ts`

**Step 1: Add imports and fields**

At the top, add the DPoP import:
```ts
import { getOAuthSettings } from '../config/oauth';
import { DPoPService } from './dpopService';
```

Add `token_type` to the `TokenResponse` usage and new fields/instance in the class:
```ts
  private tokenType: string | null = null;
  private dpop = DPoPService.getInstance();
```
In the constructor add:
```ts
    this.tokenType = localStorage.getItem('token_type');
```

**Step 2: Add `dpop_jkt` to the authorization URL**

In `getAuthorizationUrl()`, after building `params` and before the return, add:
```ts
    if (settings.dpopEnabled) {
      const jkt = await this.dpop.getThumbprint();
      params.append('dpop_jkt', jkt);
    }
```

**Step 3: Add a shared token-request helper with nonce retry**

Add this private method to the class:
```ts
  private async requestToken(
    bodyParams: Record<string, unknown>
  ): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    const tokenUrl = `${settings.baseUrl}${settings.endpoints.token}`;

    const doRequest = async (nonce?: string) => {
      let dpopProof: string | undefined;
      if (settings.dpopEnabled) {
        dpopProof = await this.dpop.createProof({
          htu: tokenUrl,
          htm: 'POST',
          nonce,
        });
      }
      const response = await fetch('/api/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tokenUrl, ...bodyParams, dpopProof }),
      });
      const data = await response.json();
      return { response, data };
    };

    let { response, data } = await doRequest();
    // DPoP-Nonce challenge: AS answers with error + nonce; retry once with nonce.
    if (settings.dpopEnabled && !response.ok && data?.dpopNonce) {
      ({ response, data } = await doRequest(data.dpopNonce));
    }
    if (!response.ok) {
      throw new Error(data?.error || 'Token request failed');
    }
    this.setTokens(data);
    return data;
  }
```

**Step 4: Rewrite the three token methods to use the helper**

`exchangeCodeForTokens`:
```ts
  public async exchangeCodeForTokens(code: string, state: string): Promise<TokenResponse> {
    if (state !== this.state) {
      throw new Error('Invalid state parameter');
    }
    if (!this.codeVerifier) {
      throw new Error('Code verifier not found. Please start the authorization flow again.');
    }
    const settings = getOAuthSettings();
    const data = await this.requestToken({
      clientId: settings.clientId,
      clientSecret: settings.clientSecret,
      code,
      redirectUri: settings.redirectUri,
      codeVerifier: this.codeVerifier,
      grantType: 'authorization_code',
      scope: settings.scope,
    });
    this.clearAuthData();
    return data;
  }
```

`getClientCredentialsToken`:
```ts
  public async getClientCredentialsToken(): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    return this.requestToken({
      clientId: settings.clientId,
      clientSecret: settings.clientSecret,
      grantType: 'client_credentials',
      scope: settings.scope,
    });
  }
```

`refreshAccessToken` (now routed through the proxy):
```ts
  public async refreshAccessToken(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }
    const settings = getOAuthSettings();
    return this.requestToken({
      clientId: settings.clientId,
      clientSecret: settings.clientSecret,
      grantType: 'refresh_token',
      refreshToken: this.refreshToken,
    });
  }
```

**Step 5: Persist `token_type` in `setTokens` and expose a getter**

Update `setTokens`:
```ts
  private setTokens(data: TokenResponse): void {
    this.accessToken = data.access_token;
    if (data.refresh_token) {
      this.refreshToken = data.refresh_token;
    }
    this.tokenType = data.token_type || (getOAuthSettings().dpopEnabled ? 'DPoP' : 'Bearer');

    localStorage.setItem('access_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
    localStorage.setItem('token_type', this.tokenType);
  }
```

Add getter near `getAccessToken`:
```ts
  public getTokenType(): string | null {
    return this.tokenType;
  }
```

Update `clearTokens` to also clear it:
```ts
  public clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenType = null;
    this.clearAuthData();
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('token_type');
  }
```

**Step 6: Typecheck**

Run: `npm run build`
Expected: build succeeds. (`getProtectedResource` still uses the old fetch here; fixed in Task 6.)

**Step 7: Commit**

```bash
git add src/services/oauthService.ts
git commit -m "feat: DPoP proofs and nonce retry on token requests"
```

---

## Task 6: `OAuthService.fetchResource` — central DPoP/Bearer resource call

**Files:**
- Modify: `src/services/oauthService.ts`

**Step 1: Add the central `fetchResource` method**

Add to the class:
```ts
  /**
   * Calls a protected URL through the proxy using DPoP (when enabled) or Bearer.
   * Handles a single DPoP-Nonce retry on 401. Returns the raw proxy Response.
   */
  public async fetchResource(url: string, method: string = 'GET'): Promise<Response> {
    if (!this.accessToken) {
      throw new Error('No access token available');
    }
    const settings = getOAuthSettings();

    const doRequest = async (nonce?: string): Promise<Response> => {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const body: Record<string, unknown> = { url, method };
      if (settings.dpopEnabled) {
        const proof = await this.dpop.createProof({
          htu: url,
          htm: method,
          nonce,
          accessToken: this.accessToken!,
        });
        headers['Authorization'] = `DPoP ${this.accessToken}`;
        body.dpopProof = proof;
      } else {
        headers['Authorization'] = `Bearer ${this.accessToken}`;
      }
      return fetch('/api/proxy', {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });
    };

    let response = await doRequest();
    if (settings.dpopEnabled && response.status === 401) {
      const nonce = response.headers.get('dpop-nonce');
      if (nonce) {
        response = await doRequest(nonce);
      }
    }
    return response;
  }
```

**Step 2: Rewrite `getProtectedResource` to use it**

Replace the body of `getProtectedResource()` with:
```ts
  public async getProtectedResource(): Promise<any> {
    if (!this.accessToken) {
      throw new Error('No access token available');
    }
    const settings = getOAuthSettings();
    console.log('Requesting protected resource:', settings.protectedResource);

    try {
      const response = await this.fetchResource(settings.protectedResource, 'GET');
      console.log('Protected resource response status:', response.status);

      if (!response.ok) {
        if (response.status === 401 && this.refreshToken) {
          console.log('Access token expired, refreshing...');
          await this.refreshAccessToken();
          return this.getProtectedResource();
        }
        const errorData = await response.text();
        console.error('Protected resource error:', errorData);
        try {
          const jsonError = JSON.parse(errorData);
          throw new Error(`Failed to get protected resource: ${jsonError.error || 'Unknown error'}`);
        } catch (e) {
          throw new Error(`Failed to get protected resource: ${errorData || response.statusText}`);
        }
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return response.json();
      } else {
        const text = await response.text();
        try {
          return JSON.parse(text);
        } catch (e) {
          return { text };
        }
      }
    } catch (error) {
      console.error('Error fetching protected resource:', error);
      throw error;
    }
  }
```

**Step 3: Typecheck**

Run: `npm run build`
Expected: build succeeds.

**Step 4: Commit**

```bash
git add src/services/oauthService.ts
git commit -m "feat: central fetchResource with DPoP support for protected resource"
```

---

## Task 7: `PerformanceService` — route connector calls through `fetchResource`

**Files:**
- Modify: `src/services/performanceService.ts` (the `testConnector` method, lines ~111-159)

**Step 1: Replace the fetch in `testConnector`**

Replace:
```ts
      const response = await fetch('/api/proxy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({ url: connector.url })
      });
```
With:
```ts
      const response = await this.oauthService.fetchResource(connector.url, 'GET');
```

(The surrounding `startTime`/`endTime` timing and `accessToken` guard stay; `accessToken` is still fetched earlier for the guard.)

**Step 2: Typecheck**

Run: `npm run build`
Expected: build succeeds.

**Step 3: Commit**

```bash
git add src/services/performanceService.ts
git commit -m "feat: use DPoP-aware fetchResource for connector performance calls"
```

---

## Task 8: OAuth Settings UI — the "Enable DPoP" checkbox

**Files:**
- Modify: `src/components/OAuthSettings.tsx`

**Step 1: Add DPoP status to the read-only view**

In the read-only grid (after the Scope block, before the closing `</div>` of `grid`), add:
```tsx
            <div>
              <p className="text-sm font-medium text-gray-500">DPoP (RFC 9449)</p>
              <p className="text-sm text-gray-900">{settings.dpopEnabled ? 'Enabled' : 'Disabled'}</p>
            </div>
```

**Step 2: Add the checkbox to the edit view**

In the edit form's `space-y-4` container (after the Scope input block), add:
```tsx
          <div className="flex items-center">
            <input
              id="dpop-enabled"
              type="checkbox"
              checked={settings.dpopEnabled}
              onChange={(e) => setSettings({ ...settings, dpopEnabled: e.target.checked })}
              className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <label htmlFor="dpop-enabled" className="ml-2 block text-sm font-medium text-gray-700">
              Enable DPoP (RFC 9449) — sender-constrained tokens
            </label>
          </div>
```

**Step 3: Typecheck + lint**

Run: `npm run build`
Run: `npm run lint`
Expected: both succeed.

**Step 4: Commit**

```bash
git add src/components/OAuthSettings.tsx
git commit -m "feat: add Enable DPoP checkbox to OAuth settings"
```

---

## Task 9: Token-type status indicator in `App.tsx`

**Files:**
- Modify: `src/App.tsx`

**Step 1: Track token type + thumbprint in state**

Add imports:
```tsx
import { DPoPService } from './services/dpopService'
import { getOAuthSettings } from './config/oauth'
```

Add state in `MainContent`:
```tsx
  const [tokenType, setTokenType] = useState<string | null>(null)
  const [dpopThumbprint, setDpopThumbprint] = useState<string | null>(null)
```

In the mount `useEffect`, after setting tokens, add:
```tsx
    setTokenType(oauthService.getTokenType())
    if (getOAuthSettings().dpopEnabled) {
      DPoPService.getInstance().getThumbprint().then(setDpopThumbprint).catch(() => {})
    }
```

Update `handleClientCredentialsFlow` (after `setAccessToken`) and `handleClearTokens` to refresh `tokenType`:
```tsx
      setAccessToken(response.access_token)
      setTokenType(oauthService.getTokenType())
```
and in `handleClearTokens`:
```tsx
    setTokenType(null)
```

**Step 2: Render the indicator**

Directly above each `Access Token:` `<pre>` (both flow branches), add:
```tsx
                              <p className="text-xs text-gray-500 mb-1">
                                Token type: <span className="font-semibold">{tokenType || 'Bearer'}</span>
                                {tokenType === 'DPoP' && dpopThumbprint && (
                                  <span> · jkt: <span className="font-mono">{dpopThumbprint}</span></span>
                                )}
                              </p>
```

**Step 3: Typecheck + lint**

Run: `npm run build`
Run: `npm run lint`
Expected: both succeed.

**Step 4: Commit**

```bash
git add src/App.tsx
git commit -m "feat: show token type and DPoP thumbprint in UI"
```

---

## Task 10: Full verification

**Step 1: Build + lint**

Run: `npm run build`
Run: `npm run lint`
Expected: both pass with no errors.

**Step 2: Restart both windows**
- Backend: `node server/server.cjs` (port 8080)
- Frontend: `npm run dev` (port 3000)

**Step 3: Manual DPoP-off regression**
- In OAuth Settings, leave DPoP unchecked.
- Run a flow, confirm token appears and shows "Token type: Bearer".
- Click "Get Protected Resource" — confirm the backend log shows `Authorization: Bearer ...` behaviour is unchanged.

**Step 4: Manual DPoP-on test**
- Edit Settings, check "Enable DPoP", Save.
- Run the flow. In the backend console confirm a `DPoP` header is sent to the token endpoint; UI shows "Token type: DPoP" + a `jkt` value.
- Click "Get Protected Resource"; confirm `Authorization: DPoP <token>` + a `DPoP` proof header reach the resource server.
- If your AS/RS requires a nonce, confirm the request retries automatically after the first `DPoP-Nonce` challenge (visible as two backend log lines for one action).
- Optionally copy a proof from the network tab into https://jwt.io and verify `htu`, `htm`, `iat`, `jti`, `ath` (resource) / `nonce` (when challenged).

**Step 5: Final commit (if any doc/tweaks remain)**

```bash
git add -A
git commit -m "chore: DPoP verification tweaks"
```

---

## Notes / gotchas
- `htu` excludes query and fragment (RFC 9449 §4.2). If your resource URL has query params, that is expected.
- The AS nonce (token endpoint) and RS nonce (resource) are independent; each is handled at its own call site with a single retry.
- If tokens exist but the DPoP key was cleared, resource calls will fail with 401 — use "Clear Tokens" and re-authenticate (or `DPoPService.getInstance().reset()` regenerates on next use).
- `dpop_jkt` on the authorization request is optional per spec; included here for a complete binding.
