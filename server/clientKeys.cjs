// Client keys for private_key_jwt (RFC 7523): one keypair per algorithm, each with a self-signed
// certificate so the public key can be registered at the server either via jwks_uri or by uploading
// the certificate. Keys live on the proxy only; the browser never sees the private half.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// @peculiar/x509 pulls in tsyringe, which refuses to load without this polyfill.
require('reflect-metadata');
const x509 = require('@peculiar/x509');

x509.cryptoProvider.set(crypto.webcrypto);

const KEYS_FILE = path.join(__dirname, 'keys', 'client-keys.json');
const CERT_VALIDITY_YEARS = 10;
const ASSERTION_LIFETIME_SECONDS = 60;

const ALGORITHMS = {
  RS256: {
    generate: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    publicMembers: ['kty', 'n', 'e'],
    // RFC 7638 canonical member order for the thumbprint.
    thumbprintMembers: ['e', 'kty', 'n'],
    sign: (key, data) => crypto.sign('sha256', data, key),
  },
  ES256: {
    generate: { name: 'ECDSA', namedCurve: 'P-256' },
    publicMembers: ['kty', 'crv', 'x', 'y'],
    thumbprintMembers: ['crv', 'kty', 'x', 'y'],
    // JOSE wants raw r||s, not the DER that Node produces by default.
    sign: (key, data) => crypto.sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' }),
  },
};

/** @type {Record<string, {privateJwk: object, publicJwk: object, kid: string, certPem: string}>} */
let keys = {};
let readyPromise = null;

function base64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function thumbprint(jwk, members) {
  const canonical = JSON.stringify(Object.fromEntries(members.map((m) => [m, jwk[m]])));
  return base64url(crypto.createHash('sha256').update(canonical).digest());
}

function certDer(certPem) {
  return Buffer.from(new x509.X509Certificate(certPem).rawData);
}

async function generate(alg) {
  const spec = ALGORITHMS[alg];
  const pair = await crypto.webcrypto.subtle.generateKey(spec.generate, true, ['sign', 'verify']);
  const privateJwk = await crypto.webcrypto.subtle.exportKey('jwk', pair.privateKey);
  const rawPublic = await crypto.webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const publicJwk = Object.fromEntries(spec.publicMembers.map((m) => [m, rawPublic[m]]));

  const notBefore = new Date();
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notAfter.getFullYear() + CERT_VALIDITY_YEARS);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    name: `CN=oauth_test_app ${alg}`,
    notBefore,
    notAfter,
    signingAlgorithm: spec.generate,
    keys: pair,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      await x509.SubjectKeyIdentifierExtension.create(pair.publicKey),
    ],
  });

  return {
    privateJwk,
    publicJwk,
    kid: thumbprint(publicJwk, spec.thumbprintMembers),
    certPem: cert.toString('pem'),
  };
}

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
    return typeof parsed === 'object' && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
}

function save() {
  fs.mkdirSync(path.dirname(KEYS_FILE), { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

/** Loads the stored keys and generates whichever algorithm is still missing. */
function ready() {
  if (!readyPromise) {
    readyPromise = (async () => {
      keys = load();
      let changed = false;
      for (const alg of Object.keys(ALGORITHMS)) {
        if (!keys[alg]?.privateJwk || !keys[alg]?.certPem) {
          console.log(`Generating ${alg} client key and certificate...`);
          keys[alg] = await generate(alg);
          changed = true;
        }
      }
      if (changed) save();
      return keys;
    })();
  }
  return readyPromise;
}

function getJwks() {
  return {
    keys: Object.entries(keys).map(([alg, entry]) => {
      const der = certDer(entry.certPem);
      return {
        ...entry.publicJwk,
        kid: entry.kid,
        use: 'sig',
        alg,
        x5c: [der.toString('base64')],
        'x5t#S256': base64url(crypto.createHash('sha256').update(der).digest()),
      };
    }),
  };
}

/** @returns {{der: Buffer, pem: string} | null} */
function getCertificate(alg) {
  const entry = keys[alg];
  if (!entry) return null;
  return { der: certDer(entry.certPem), pem: entry.certPem };
}

function isSupportedAlgorithm(alg) {
  return Object.prototype.hasOwnProperty.call(ALGORITHMS, alg);
}

/**
 * Builds the client_assertion JWT (RFC 7523 §3). The header carries kid, x5t and x5t#S256 so the
 * server can locate the key whether it was registered via jwks_uri or as an uploaded certificate.
 */
function signClientAssertion({ alg, clientId, audience }) {
  const spec = ALGORITHMS[alg];
  const entry = keys[alg];
  if (!spec || !entry) throw new Error(`Unsupported client assertion algorithm: ${alg}`);

  const der = certDer(entry.certPem);
  const header = {
    alg,
    typ: 'JWT',
    kid: entry.kid,
    x5t: base64url(crypto.createHash('sha1').update(der).digest()),
    'x5t#S256': base64url(crypto.createHash('sha256').update(der).digest()),
  };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientId,
    sub: clientId,
    aud: audience,
    jti: base64url(crypto.randomBytes(16)),
    iat: now,
    exp: now + ASSERTION_LIFETIME_SECONDS,
  };

  const signingInput =
    `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const privateKey = crypto.createPrivateKey({ key: entry.privateJwk, format: 'jwk' });
  const signature = spec.sign(privateKey, Buffer.from(signingInput));
  return `${signingInput}.${base64url(signature)}`;
}

module.exports = { ready, getJwks, getCertificate, isSupportedAlgorithm, signClientAssertion };
