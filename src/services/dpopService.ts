// DPoP (RFC 9449) helper: ES256 (EC P-256) keypair management + proof-JWT generation.
// The private key never leaves the browser; the public JWK is embedded in each proof.

import { findFault, type DpopFaultKey } from "./dpopFaults";

interface StoredKeyPair {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

const STORAGE_KEY = "dpop_keypair";
const NONCE_STORAGE_KEY = "dpop_nonces";
const FAULT_STORAGE_KEY = "dpop_armed_fault";
const JTI_STORAGE_KEY = "dpop_last_jti";

/**
 * Which server issued a nonce. RFC 9449 §9: "a nonce issued by any of them should be used only at
 * the issuing server", so an authorization-server nonce must never be replayed at a resource server.
 * They are tracked separately even when both happen to live on the same origin.
 */
export type NonceScope = "as" | "rs";

export class DPoPService {
  private static instance: DPoPService;
  private keyPairPromise: Promise<CryptoKeyPair> | null = null;
  private publicJwk: JsonWebKey | null = null;
  private nonces: Record<string, string> = loadNonces();

  /**
   * The fault every proof will carry until it is disarmed.
   *
   * Persisted rather than kept in memory because the authorization code flow leaves the page: the
   * redirect to the authorization server and back rebuilds this service, and an in-memory fault
   * would be gone exactly when the token exchange needs it.
   */
  private armedFault: DpopFaultKey | null = loadArmedFault();
  private armedListeners = new Set<(fault: DpopFaultKey | null) => void>();

  /**
   * The last jti actually sent. Kept so the replay scenario can resend it: the server only counts it
   * as a replay if it recorded that exact value, so inventing one would test nothing.
   */
  private lastJti: string | null = loadLastJti();

  public static getInstance(): DPoPService {
    if (!DPoPService.instance) {
      DPoPService.instance = new DPoPService();
    }
    return DPoPService.instance;
  }

  /**
   * Arms a single fault, which stays armed until it is cleared. Deliberately replaces rather than
   * accumulates: with two faults active the server stops at whichever check runs first, so the
   * outcome would no longer say anything about the scenario that was selected.
   */
  public armFault(fault: DpopFaultKey | null): void {
    this.armedFault = fault;
    try {
      if (fault) {
        localStorage.setItem(FAULT_STORAGE_KEY, fault);
      } else {
        localStorage.removeItem(FAULT_STORAGE_KEY);
      }
    } catch {
      // Storage unavailable — the in-memory copy still covers this page load.
    }
    this.armedListeners.forEach((listener) => listener(fault));
  }

  public getArmedFault(): DpopFaultKey | null {
    return this.armedFault;
  }

  /** Lets the warning banner follow the armed fault across components. */
  public onArmedFaultChange(listener: (fault: DpopFaultKey | null) => void): () => void {
    this.armedListeners.add(listener);
    return () => this.armedListeners.delete(listener);
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
    /**
     * Fault to apply to this proof. When omitted the armed fault is used and consumed; pass null to
     * explicitly build a clean proof. The suite passes it directly so it never races the UI state.
     */
    fault?: DpopFaultKey | null;
  }): Promise<string> {
    const fault = opts.fault !== undefined ? opts.fault : this.armedFault;

    const keyPair = await this.getKeyPair();
    const publicJwk = await this.getPublicJwk();

    const header: Record<string, unknown> = { typ: "dpop+jwt", alg: "ES256", jwk: publicJwk };

    const jti = fault === "jti-reuse" && this.lastJti ? this.lastJti : generateJti();
    const payload: Record<string, unknown> = {
      jti,
      htm: opts.htm.toUpperCase(),
      htu: normalizeHtu(opts.htu),
      iat: Math.floor(Date.now() / 1000),
    };
    if (opts.nonce) payload.nonce = opts.nonce;
    if (opts.accessToken) payload.ath = await accessTokenHash(opts.accessToken);

    switch (fault) {
      case "typ-wrong":
        header.typ = "jwt";
        break;
      case "alg-hs256":
        header.alg = "HS256";
        break;
      case "alg-none":
        header.alg = "none";
        break;
      case "jwk-missing":
        delete header.jwk;
        break;
      case "jwk-other":
        // Signed with the real key but advertising another one, which catches a server that reads
        // jwk without verifying the signature against it.
        header.jwk = await unrelatedPublicJwk();
        break;
      case "htm-wrong":
        payload.htm = opts.htm.toUpperCase() === "POST" ? "GET" : "POST";
        break;
      case "htu-wrong":
        payload.htu = `${normalizeHtu(opts.htu)}/somewhere-else`;
        break;
      case "iat-past":
        payload.iat = Math.floor(Date.now() / 1000) - 3600;
        break;
      case "iat-future":
        payload.iat = Math.floor(Date.now() / 1000) + 3600;
        break;
      case "jti-missing":
        delete payload.jti;
        break;
      case "nonce-missing":
        delete payload.nonce;
        break;
      case "nonce-garbage":
        payload.nonce = `not-a-real-nonce-${generateJti()}`;
        break;
      case "ath-missing":
        delete payload.ath;
        break;
      case "ath-wrong":
        payload.ath = await accessTokenHash("a-completely-different-access-token");
        break;
    }

    // Remembered only when actually sent: a proof without jti records nothing server-side, so
    // carrying it over would make a later replay test compare against something never seen.
    // Persisted for the same reason as the armed fault: the token exchange happens after a redirect.
    if (typeof payload.jti === "string") {
      this.lastJti = payload.jti;
      try {
        localStorage.setItem(JTI_STORAGE_KEY, payload.jti);
      } catch {
        // Storage unavailable — the in-memory copy still covers this page load.
      }
    }

    const encodedHeader = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(header))
    );
    const encodedPayload = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(payload))
    );
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // The unsigned-token attack: alg none is only a real test when the signature is genuinely absent.
    if (fault === "alg-none") {
      return `${signingInput}.`;
    }

    // WebCrypto ECDSA output is raw r||s (IEEE P1363) === JOSE format. No DER conversion.
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      new TextEncoder().encode(signingInput)
    );
    let encodedSignature = base64UrlEncode(new Uint8Array(signature));

    // Damaged after signing, so every other part of the proof stays valid and only the signature
    // check can be the reason for rejection.
    if (fault === "signature-corrupt") {
      encodedSignature = corruptSignature(encodedSignature);
    }

    return `${signingInput}.${encodedSignature}`;
  }

  /** Forget the current key (a new one is generated on next use). */
  public reset(): void {
    localStorage.removeItem(STORAGE_KEY);
    this.keyPairPromise = null;
    this.publicJwk = null;
    // Nonces are bound to the key thumbprint by the server, so a new key invalidates all of them.
    this.nonces = {};
    localStorage.removeItem(NONCE_STORAGE_KEY);
    // The replay key is the thumbprint combined with the jti, so a jti recorded under the old key
    // would no longer collide and the replay scenario would silently pass.
    this.lastJti = null;
    localStorage.removeItem(JTI_STORAGE_KEY);
    this.armFault(null);
  }

  /**
   * The nonce currently held for this server, or undefined when none was issued yet.
   * RFC 9449 §8: "clients need to keep only one nonce value" per issuing server.
   */
  public getNonce(scope: NonceScope, url: string): string | undefined {
    return this.nonces[nonceKey(scope, url)];
  }

  /**
   * Adopts a nonce supplied by the server. Call this for every response, not just the
   * use_dpop_nonce challenge: RFC 9449 §8.2 also rotates the nonce on a successful response, which
   * is what avoids paying an extra round trip on every single request.
   */
  public rememberNonce(scope: NonceScope, url: string, nonce: string | null | undefined): void {
    if (!nonce) {
      return;
    }
    this.nonces[nonceKey(scope, url)] = nonce;
    try {
      localStorage.setItem(NONCE_STORAGE_KEY, JSON.stringify(this.nonces));
    } catch {
      // Storage full or unavailable — the in-memory copy still works for this session.
    }
  }
}

/** Nonces are per issuing server, and the scope keeps AS and RS apart on a shared origin. */
function nonceKey(scope: NonceScope, url: string): string {
  let origin: string;
  try {
    origin = new URL(url).origin;
  } catch {
    origin = url;
  }
  return `${scope}|${origin}`;
}

/**
 * Restores the armed fault after a page load. The stored value is checked against the catalogue,
 * because localStorage is writable by anything on this origin and an unknown key would silently
 * behave as "no fault" while the banner claimed otherwise.
 */
function loadArmedFault(): DpopFaultKey | null {
  try {
    const stored = localStorage.getItem(FAULT_STORAGE_KEY);
    return stored && findFault(stored as DpopFaultKey) ? (stored as DpopFaultKey) : null;
  } catch {
    return null;
  }
}

function loadLastJti(): string | null {
  try {
    return localStorage.getItem(JTI_STORAGE_KEY);
  } catch {
    return null;
  }
}

function loadNonces(): Record<string, string> {  try {
    const stored = localStorage.getItem(NONCE_STORAGE_KEY);
    if (!stored) {
      return {};
    }
    const parsed: unknown = JSON.parse(stored);
    // localStorage is writable by anything on this origin, so treat the contents as untrusted.
    // null would make indexing throw, and assigning onto a primitive throws in strict mode
    // (ES modules are always strict), which would break rememberNonce on every request.
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return {};
    }
    // Drop non-string values as well: they would end up in the nonce claim of a proof.
    return Object.fromEntries(
      Object.entries(parsed).filter(([, value]) => typeof value === "string")
    ) as Record<string, string>;
  } catch {
    return {};
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

/** A throwaway public key, for advertising a jwk that did not sign the proof. */
async function unrelatedPublicJwk(): Promise<JsonWebKey> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/**
 * Alters one character of the signature while keeping it valid base64url and the same length, so the
 * proof still parses and fails on verification rather than on decoding.
 */
function corruptSignature(encodedSignature: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = encodedSignature.slice(-1);
  const replacement = alphabet[(alphabet.indexOf(last) + 1) % alphabet.length];
  return encodedSignature.slice(0, -1) + replacement;
}

function base64UrlEncode(buffer: Uint8Array): string {
  let str = "";
  for (let i = 0; i < buffer.length; i++) {
    str += String.fromCharCode(buffer[i]);
  }
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
