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
