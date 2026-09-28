# OAuth 2.1 Test Application

A modern React application for testing OAuth 2.1 flows, built with TypeScript and Tailwind CSS. This application supports both Authorization Code Flow (with PKCE) and Client Credentials Flow.

## Features

- 🔐 Support for OAuth 2.1 flows:
  - Authorization Code Flow with PKCE
  - Client Credentials Flow
- 🔑 Client authentication with `client_secret_post`, `client_secret_basic` or `private_key_jwt`
  (RFC 7523), with a self-hosted `jwks_uri` and downloadable certificates
- 🧪 Deliberately malformed authorize requests and DPoP proofs, to check how the server rejects them
- 🛠️ Configurable OAuth settings through web UI
- 💾 Token persistence
- 🔄 Automatic token refresh
- 🎨 Modern UI with Tailwind CSS

## Prerequisites

- Node.js >= 18.0.0
- npm or yarn

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/maui1911/oauth_test_app.git
   cd oauth_test_app
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the backend OAuth proxy server:
   ```bash
   node server/server.cjs
   ```
   This will start the backend on `http://localhost:8080`.

4. In a separate terminal, start the frontend development server:
   ```bash
   npm run dev
   ```
   The application will be available at `http://localhost:3000`.

## How it works

- The frontend (React/Vite) runs on port 3000.
- The backend Node.js proxy (server/server.cjs) runs on port 8080 and handles all OAuth token exchanges, avoiding CORS issues and keeping credentials secure.
- The Vite dev server proxies all `/api` requests to the backend.
- For production, you should set up a reverse proxy (e.g., Nginx) to forward `/api` requests to the backend server.

## Debugging

- The backend server logs all incoming requests, OAuth server responses, and errors to the console for easier debugging.
- If you encounter SSL certificate issues with self-signed certificates, SSL verification is disabled for development in `server/server.cjs`.

## Configuration

The application allows you to configure OAuth settings through the web UI. All settings are persisted in localStorage and include:

- Base URL: The base URL of your OAuth server
- Client ID: Your OAuth client ID
- Client authentication: `client_secret_post` (default), `client_secret_basic` or `private_key_jwt`
- Client Secret: Your OAuth client secret (not for `private_key_jwt`). With `client_secret_basic`
  you can choose to send `client_id` in the body as well.
- Assertion algorithm, assertion audience and JWKS public URL (only for `private_key_jwt`, see below)
- Redirect URI: The callback URL for the Authorization Code flow
- Protected Resource: The URL of your protected resource endpoint
- Scope: The OAuth scope (default: "openid profile email")

To configure your OAuth settings:
1. Click the "Edit Settings" button in the OAuth Settings panel
2. Enter your OAuth configuration details
3. Click "Save Changes" to apply the settings

You can also reset to default settings using the "Reset to Default" button.

### private_key_jwt

With `private_key_jwt` the proxy authenticates the client with a signed JWT (`client_assertion`)
instead of a shared secret. On first start the proxy generates an RSA-2048 and an EC P-256 keypair,
each with a self-signed certificate, and stores them in `server/keys/client-keys.json` (gitignored).
Delete that file and restart to rotate the keys.

Register the public key at the authorization server in one of two ways:

- **jwks_uri**: `http://localhost:8080/api/jwks` (or `http://localhost:3000/api/jwks` through the
  Vite proxy). If the authorization server runs on another machine, set "JWKS public URL" in the
  settings to the address it can reach; the UI shows that value with a copy button.
- **Certificate upload**: download the DER (`.cer`) or PEM certificate for the chosen algorithm from
  `/api/client-cert/RS256.cer`, `/api/client-cert/ES256.cer` or the `.pem` variants. The UI offers
  these as download buttons.

The assertion header carries `kid` (RFC 7638 thumbprint), `x5t` and `x5t#S256`, so servers can
locate the key by either the JWKS entry or the certificate. The `aud` claim is configurable: the
token endpoint URL (default), the issuer (base URL) or a custom value. Each assertion is valid for
60 seconds and carries a fresh `jti`. The UI shows the assertion (raw and decoded) after every
token request, including rejected ones.

### Error responses

Errors from the authorization endpoint come back as a redirect to the callback. The app shows
`error`, `error_description` and whether the returned `state` matches the one it sent. The
"Authorize request" selector sends a deliberately malformed request (no `code_challenge`,
`response_type=token`, a duplicated `state`, a redirect URI in other case) and shows the expected
outcome next to it.

Token endpoint and resource errors show the HTTP status, `error`, `error_description` and the
`WWW-Authenticate` challenge. The proxy passes the token endpoint's challenge in its JSON body rather
than as a header, because a 401 with a Basic challenge would make the browser prompt for a login.
"Call without token" calls the protected resource without credentials, to see the challenge it
answers with.

When a resource call returns `error="invalid_token"`, the app renews the token once (via the
refresh token, or a new client credentials request) and repeats the call. Other 401s, such as a
DPoP proof or nonce problem, are shown as they are.

## Development

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build

## Project Structure

```
├── server/                # Backend Node.js proxy
│   └── server.cjs
├── src/                   # Frontend React app
│   ├── components/
│   ├── config/
│   ├── services/
│   └── ...
└── public/                # Static files
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License - see the LICENSE file for details.