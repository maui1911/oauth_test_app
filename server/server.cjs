process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Simple Express backend for OAuth token exchange
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
const clientKeys = require('./clientKeys.cjs');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(bodyParser.json());

// Proxy endpoint for OAuth token exchange
app.post('/api/oauth/token', async (req, res) => {
  console.log('Received /api/oauth/token request:', req.body);
  const {
    tokenUrl, clientId, clientSecret, code, redirectUri,
    codeVerifier, grantType, scope, refreshToken, dpopProof,
    clientAuthMethod, clientAssertionAlg, clientAssertionAudience
  } = req.body;
  try {
    const params = new URLSearchParams();
    params.append('client_id', clientId);
    if (clientAuthMethod === 'private_key_jwt') {
      if (!clientKeys.isSupportedAlgorithm(clientAssertionAlg)) {
        return res.status(400).json({ error: `Unsupported client assertion algorithm: ${clientAssertionAlg}` });
      }
      const assertion = clientKeys.signClientAssertion({
        alg: clientAssertionAlg,
        clientId,
        audience: clientAssertionAudience || tokenUrl,
      });
      params.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      params.append('client_assertion', assertion);
      // Exposed on success and failure alike: a rejected assertion is exactly what needs inspecting.
      res.set('X-Client-Assertion', assertion);
    } else if (clientSecret) {
      params.append('client_secret', clientSecret);
    }
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

// Public keys for private_key_jwt, to be registered at the authorization server as jwks_uri.
app.get('/api/jwks', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(clientKeys.getJwks());
});

// The same public keys as self-signed certificates, for servers that take an upload instead of a URI.
app.get('/api/client-cert/:file', (req, res) => {
  const match = /^([A-Za-z0-9]+)\.(cer|pem)$/.exec(req.params.file);
  const cert = match && clientKeys.getCertificate(match[1]);
  if (!cert) {
    return res.status(404).json({ error: `Unknown client certificate: ${req.params.file}` });
  }
  const [, alg, format] = match;
  res.set('Content-Disposition', `attachment; filename="oauth_test_app-${alg}.${format}"`);
  if (format === 'cer') {
    res.type('application/pkix-cert').send(cert.der);
  } else {
    res.type('application/x-pem-file').send(cert.pem);
  }
});

// Proxy endpoint for connector calls
app.post('/api/proxy', async (req, res) => {
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
    
    // Clean up problematic headers to avoid conflicts
    const headersToSend = { ...response.headers };
    // Remove problematic headers (case-insensitive)
    Object.keys(headersToSend).forEach((key) => {
      if ([
        'content-encoding',
        'content-length',
        'transfer-encoding',
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailer',
        'upgrade'
      ].includes(key.toLowerCase())) {
        delete headersToSend[key];
      }
    });
    
    // Set status and headers then send the data
    res.status(response.status);
    Object.entries(headersToSend).forEach(([key, value]) => {
      if (typeof value === 'string') {
        res.set(key, value);
      }
    });
    // Use res.send instead of res.json to avoid Express re-encoding
    res.send(response.data);
  } catch (error) {
    console.error('Error in /api/proxy:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response headers:', error.response.headers);
      console.error('Response data:', error.response.data);
    }
    res.status(error.response?.status || 500).json({ error: error.message, details: error.response?.data });
  }
});

clientKeys.ready().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`OAuth proxy server running on port ${PORT}`);
    console.log(`Client JWKS available at http://localhost:${PORT}/api/jwks`);
  });
}).catch((error) => {
  console.error('Failed to prepare client keys:', error);
  process.exit(1);
});