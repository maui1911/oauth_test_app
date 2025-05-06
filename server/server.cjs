process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Simple Express backend for OAuth token exchange
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(bodyParser.json());

// Proxy endpoint for OAuth token exchange
app.post('/api/oauth/token', async (req, res) => {
  console.log('Received /api/oauth/token request:', req.body); // Log request body
  const { tokenUrl, clientId, clientSecret, code, redirectUri, codeVerifier, grantType, scope } = req.body;
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
    }
    const response = await axios.post(tokenUrl, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    console.log('OAuth server response:', response.data); // Log OAuth server response
    res.json(response.data);
  } catch (error) {
    console.error('Error in /api/oauth/token:', error.response?.data || error.message); // Log error details
    res.status(error.response?.status || 500).json({ error: error.message, details: error.response?.data });
  }
});

// Proxy endpoint for connector calls
app.post('/api/proxy', async (req, res) => {
  const { url } = req.body;
  const authHeader = req.headers['authorization'];
  console.log('Proxying connector call to:', url);
  try {
    const response = await axios.get(url, {
      headers: authHeader ? { Authorization: authHeader } : {},
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`OAuth proxy server running on port ${PORT}`);
});