import { getOAuthSettings, getTokenUrl, resolveClientAssertionAudience } from '../config/oauth';
import { applyAuthorizeVariant, findAuthorizeVariant, type AuthorizeVariantKey } from './authorizeVariants';
import { findFault, type DpopFaultKey } from './dpopFaults';
import { DPoPService } from './dpopService';
import { challengeParam } from './wwwAuthenticate';

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
}

/** The grants that start a session; a refresh continues the session that is already there. */
type SessionGrant = 'authorization_code' | 'client_credentials';
type TokenGrant = SessionGrant | 'refresh_token';

export class OAuthService {
  private static instance: OAuthService;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private codeVerifier: string | null = null;
  private state: string | null = null;
  private tokenType: string | null = null;
  private sessionGrant: SessionGrant | null = null;
  private lastDpopProof: string | null = null;
  private lastClientAssertion: string | null = null;
  private lastAuthorizationOutcome: string | null = null;
  private lastRenewalChallenge: string | null = null;
  private dpop = DPoPService.getInstance();

  private constructor() {
    // Load tokens from localStorage on initialization
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
    this.codeVerifier = localStorage.getItem('code_verifier');
    this.state = localStorage.getItem('oauth_state');
    this.tokenType = localStorage.getItem('token_type');
    const grant = localStorage.getItem('token_grant');
    this.sessionGrant = grant === 'authorization_code' || grant === 'client_credentials' ? grant : null;
  }

  public static getInstance(): OAuthService {
    if (!OAuthService.instance) {
      OAuthService.instance = new OAuthService();
    }
    return OAuthService.instance;
  }

  private generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
  }

  private async generateCodeChallenge(verifier: string): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64URLEncode(new Uint8Array(hash));
  }

  public async getAuthorizationUrl(variant: AuthorizeVariantKey = 'none'): Promise<string> {
    const settings = getOAuthSettings();
    this.codeVerifier = this.generateCodeVerifier();
    this.state = this.generateState();
    const codeChallenge = await this.generateCodeChallenge(this.codeVerifier);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: settings.clientId,
      redirect_uri: settings.redirectUri,
      scope: settings.scope,
      state: this.state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    if (settings.dpopEnabled) {
      const jkt = await this.dpop.getThumbprint();
      params.append('dpop_jkt', jkt);
    }

    applyAuthorizeVariant(params, variant);

    // The callback runs after a full page load, and the code exchange must repeat the exact
    // redirect_uri that was sent here (RFC 6749 §4.1.3), which a variant may have altered.
    localStorage.setItem('code_verifier', this.codeVerifier);
    localStorage.setItem('oauth_state', this.state);
    localStorage.setItem('oauth_redirect_uri', params.get('redirect_uri') ?? settings.redirectUri);
    localStorage.setItem('authorize_variant', variant);

    return `${settings.baseUrl}${settings.endpoints.authorize}?${params.toString()}`;
  }

  /**
   * Handles the redirect back from the authorization server. Never throws: the outcome is kept for
   * the page the callback navigates to, because the callback route itself is gone by then.
   */
  public async completeAuthorization(params: URLSearchParams): Promise<void> {
    const variant = findAuthorizeVariant(localStorage.getItem('authorize_variant'));
    const sentRedirectUri = localStorage.getItem('oauth_redirect_uri') ?? getOAuthSettings().redirectUri;
    const stateCheck = this.describeReturnedState(params.getAll('state'));
    const expectation = variant.key === 'none' ? [] : [`Request sent: ${variant.label}. Expected: ${variant.expected}`];
    this.lastAuthorizationOutcome = null;

    try {
      const error = params.get('error');
      if (error) {
        const description = params.get('error_description');
        this.lastAuthorizationOutcome = [
          `Authorization failed: ${error}${description ? ` — ${description}` : ''}`,
          stateCheck,
          ...expectation,
        ].join('\n');
        return;
      }

      const code = params.get('code');
      if (!code) {
        throw new Error('The callback carried neither a code nor an error.');
      }
      if (!this.state || params.get('state') !== this.state) {
        throw new Error(`Invalid state parameter (${stateCheck})`);
      }
      if (!this.codeVerifier) {
        throw new Error('Code verifier not found. Please start the authorization flow again.');
      }
      const settings = getOAuthSettings();
      await this.requestToken('authorization_code', {
        clientId: settings.clientId,
        code,
        redirectUri: sentRedirectUri,
        codeVerifier: this.codeVerifier,
        scope: settings.scope,
      });
      if (variant.expectsRejection) {
        this.lastAuthorizationOutcome = [
          'The server issued a code for a request it should have refused.',
          ...expectation,
        ].join('\n');
      }
    } catch (error) {
      this.lastAuthorizationOutcome = [
        error instanceof Error ? error.message : 'Failed to exchange code for tokens',
        ...expectation,
      ].join('\n');
    } finally {
      this.clearAuthData();
    }
  }

  private describeReturnedState(returned: string[]): string {
    if (returned.length === 0) {
      return 'state: not returned';
    }
    if (returned.length === 1 && returned[0] === this.state) {
      return 'state: returned, matches the one sent';
    }
    return `state: returned but does not match the one sent (${returned.join(', ')})`;
  }

  private async requestToken(
    grant: TokenGrant,
    bodyParams: Record<string, unknown>
  ): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    const tokenUrl = getTokenUrl(settings);
    const armedFault = this.dpop.getArmedFault();

    const clientAuth: Record<string, unknown> = { clientAuthMethod: settings.clientAuthMethod };
    if (settings.clientAuthMethod === 'private_key_jwt') {
      // The proxy signs the client_assertion, since only it holds the private key.
      clientAuth.clientAssertionAlg = settings.clientAssertionAlg;
      clientAuth.clientAssertionAudience = resolveClientAssertionAudience(settings);
    } else {
      clientAuth.clientSecret = settings.clientSecret;
      clientAuth.basicClientIdInBody = settings.basicClientIdInBody;
    }

    this.lastClientAssertion = null;

    const doRequest = async (nonce?: string, clientAssertion?: string) => {
      const dpopProof = settings.dpopEnabled
        ? await this.buildDpopHeader({ htu: tokenUrl, htm: 'POST', nonce }, armedFault)
        : undefined;
      const response = await fetch('/api/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tokenUrl,
          grantType: grant,
          ...bodyParams,
          ...clientAuth,
          clientAssertion,
          dpopProof,
        }),
      });
      // Read the header before touching the body. A non-JSON error response (proxy down, gateway
      // error) must not cost us the nonce, and RFC 9449 §8.2 obliges the client to adopt it.
      const headerNonce = response.headers.get('dpop-nonce');
      this.lastClientAssertion = response.headers.get('x-client-assertion');
      const data = await readJsonOrNull(response);
      this.dpop.rememberNonce('as', tokenUrl, headerNonce ?? data?.dpopNonce);
      return { response, data };
    };

    // Start from the nonce we already hold instead of deliberately triggering a challenge.
    const currentNonce = this.dpop.getNonce('as', tokenUrl);
    let { response, data } = await doRequest(currentNonce);

    // Only retry when the server actually replaced the nonce, so a persistent failure cannot loop.
    // Never retry a deliberately faulty request: the retry would carry a clean proof and report
    // success, which hides the very rejection the fault was armed to demonstrate.
    if (settings.dpopEnabled && !response.ok && mayRetryNonce(armedFault)) {
      const refreshed = this.dpop.getNonce('as', tokenUrl);
      if (refreshed && refreshed !== currentNonce) {
        // The nonce challenge precedes client authentication, so the assertion is still unspent.
        const unspentAssertion =
          data?.error === 'use_dpop_nonce' ? this.lastClientAssertion ?? undefined : undefined;
        ({ response, data } = await doRequest(refreshed, unspentAssertion));
      }
    }
    if (!response.ok) {
      throw new Error(
        describeFailure(
          'Token request',
          response.status,
          data?.error,
          data?.details?.error_description,
          data?.challenge
        )
      );
    }
    this.setTokens(data, grant);
    return data;
  }

  public async getClientCredentialsToken(): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    return this.requestToken('client_credentials', {
      clientId: settings.clientId,
      scope: settings.scope,
    });
  }

  public async refreshAccessToken(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }
    const settings = getOAuthSettings();
    return this.requestToken('refresh_token', {
      clientId: settings.clientId,
      refreshToken: this.refreshToken,
    });
  }

  /**
   * The DPoP header value for one request. Faults that concern the header rather than the proof
   * are applied here: no proof at all, or two of them (an array goes out as two header lines).
   */
  private async buildDpopHeader(
    opts: { htu: string; htm: string; nonce?: string; accessToken?: string },
    armedFault: DpopFaultKey | null
  ): Promise<string | string[] | undefined> {
    if (armedFault === 'header-omitted') {
      return undefined;
    }
    const proof = await this.dpop.createProof(opts);
    if (armedFault === 'header-duplicate') {
      return [proof, await this.dpop.createProof(opts)];
    }
    if (armedFault === 'header-comma') {
      return `${proof}, ${await this.dpop.createProof(opts)}`;
    }
    return proof;
  }

  /**
   * Calls a protected URL through the proxy using DPoP (when enabled) or Bearer, or without any
   * credentials. Handles a single DPoP-Nonce retry on 401. Returns the raw proxy Response.
   */
  public async fetchResource(
    url: string,
    method: string = 'GET',
    options: { withoutToken?: boolean } = {}
  ): Promise<Response> {
    if (!this.accessToken && !options.withoutToken) {
      throw new Error('No access token available');
    }
    const settings = getOAuthSettings();
    const armedFault = this.dpop.getArmedFault();
    const usesDpop = settings.dpopEnabled && !options.withoutToken;

    const doRequest = async (nonce?: string): Promise<Response> => {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const body: Record<string, unknown> = { url, method };
      this.lastDpopProof = null;
      if (usesDpop) {
        // Also without a proof the token travels as DPoP, so the server rejects the missing proof
        // rather than falling back to treating this as a plain bearer request.
        headers['Authorization'] = `DPoP ${this.accessToken}`;
        const dpopHeader = await this.buildDpopHeader(
          { htu: url, htm: method, nonce, accessToken: this.accessToken! },
          armedFault
        );
        if (dpopHeader) {
          body.dpopProof = dpopHeader;
          this.lastDpopProof = Array.isArray(dpopHeader) ? dpopHeader.join('\n') : dpopHeader;
        }
      } else if (!options.withoutToken) {
        headers['Authorization'] = `Bearer ${this.accessToken}`;
      }
      return fetch('/api/proxy', {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      }).then((response) => {
        // The proxy forwards the resource server's DPoP-Nonce verbatim (RFC 9449 §9).
        this.dpop.rememberNonce('rs', url, response.headers.get('dpop-nonce'));
        return response;
      });
    };

    const currentNonce = this.dpop.getNonce('rs', url);
    let response = await doRequest(currentNonce);
    // Never retry a deliberately faulty request: a clean retry would mask the rejection.
    if (usesDpop && response.status === 401 && mayRetryNonce(armedFault)) {
      const refreshed = this.dpop.getNonce('rs', url);
      if (refreshed && refreshed !== currentNonce) {
        response = await doRequest(refreshed);
      }
    }
    return response;
  }

  /**
   * Fetches the configured protected resource. When the server rejects the token itself, the token
   * is renewed once the way it was obtained and the call repeated.
   */
  public async getProtectedResource(): Promise<any> {
    const url = getOAuthSettings().protectedResource;
    this.lastRenewalChallenge = null;

    let response = await this.fetchResource(url, 'GET');
    const challenge = response.headers.get('www-authenticate');
    // Only invalid_token blames the token; a proof or nonce problem would recur with a new one. With
    // a fault armed the rejection is the result under test, and a renewal would carry the fault too.
    if (
      response.status === 401 &&
      challengeParam(challenge, 'error') === 'invalid_token' &&
      !this.dpop.getArmedFault() &&
      this.canRenew()
    ) {
      this.lastRenewalChallenge = challenge;
      await this.renewToken();
      response = await this.fetchResource(url, 'GET');
    }
    return readResourceResponse(response);
  }

  /** Calls the protected resource with no credentials, to see which challenge it answers with. */
  public async getProtectedResourceWithoutToken(): Promise<any> {
    this.lastRenewalChallenge = null;
    const response = await this.fetchResource(getOAuthSettings().protectedResource, 'GET', {
      withoutToken: true,
    });
    return readResourceResponse(response);
  }

  private canRenew(): boolean {
    // client_credentials involves no user, so without a refresh token a new token is one request away.
    return !!this.refreshToken || this.sessionGrant === 'client_credentials';
  }

  private async renewToken(): Promise<void> {
    if (this.refreshToken) {
      await this.refreshAccessToken();
    } else {
      await this.getClientCredentialsToken();
    }
  }

  private setTokens(data: TokenResponse, grant: TokenGrant): void {
    this.accessToken = data.access_token;
    // A refresh without a new refresh token keeps the old one (RFC 6749 §6); other grants start over.
    if (data.refresh_token || grant !== 'refresh_token') {
      this.refreshToken = data.refresh_token ?? null;
    }
    if (grant !== 'refresh_token') {
      this.sessionGrant = grant;
    }
    this.tokenType = data.token_type || (getOAuthSettings().dpopEnabled ? 'DPoP' : 'Bearer');

    localStorage.setItem('access_token', data.access_token);
    storeOrRemove('refresh_token', this.refreshToken);
    storeOrRemove('token_grant', this.sessionGrant);
    localStorage.setItem('token_type', this.tokenType);
  }

  private generateState(): string {
    // Unguessable, and never empty: the server leaves an empty state out of its redirect.
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
  }

  public getAccessToken(): string | null {
    return this.accessToken;
  }

  public getTokenType(): string | null {
    return this.tokenType;
  }

  /** The DPoP proof JWT sent on the most recent resource call (null if DPoP was off). */
  public getLastDpopProof(): string | null {
    return this.lastDpopProof;
  }

  /** The client_assertion JWT sent on the most recent token request (null without private_key_jwt). */
  public getLastClientAssertion(): string | null {
    return this.lastClientAssertion;
  }

  /** What went wrong on the last return from the authorization server, or null if nothing did. */
  public getAuthorizationOutcome(): string | null {
    return this.lastAuthorizationOutcome;
  }

  /** The challenge that made the last resource call renew its token, or null if it did not. */
  public getLastRenewalChallenge(): string | null {
    return this.lastRenewalChallenge;
  }

  public getRefreshToken(): string | null {
    return this.refreshToken;
  }

  private clearAuthData(): void {
    this.codeVerifier = null;
    this.state = null;
    localStorage.removeItem('code_verifier');
    localStorage.removeItem('oauth_state');
    localStorage.removeItem('oauth_redirect_uri');
    localStorage.removeItem('authorize_variant');
  }

  public clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenType = null;
    this.sessionGrant = null;
    this.lastRenewalChallenge = null;
    this.clearAuthData();
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('token_type');
    localStorage.removeItem('token_grant');
  }
}

/** Nonce retries are skipped under a fault, except where the proof is valid and only the nonce is new. */
function mayRetryNonce(armedFault: DpopFaultKey | null): boolean {
  return !armedFault || findFault(armedFault)?.allowsNonceRetry === true;
}

/** Returns the parsed body of a successful resource call, or throws with the status and challenge. */
async function readResourceResponse(response: Response): Promise<any> {
  const text = await response.text();
  if (!response.ok) {
    const json = parseJsonObject(text);
    const error = json?.error ?? json?.message;
    let message = describeFailure(
      'Protected resource request',
      response.status,
      error,
      json?.error_description,
      response.headers.get('www-authenticate')
    );
    // A resource states its error in the challenge; the body is usually just "0" or empty.
    if (text && !error) {
      message += `\nBody: ${text}`;
    }
    throw new Error(message);
  }
  try {
    return JSON.parse(text);
  } catch {
    return { text };
  }
}

function describeFailure(
  request: string,
  status: number,
  error?: string,
  description?: string,
  challenge?: string | null
): string {
  let message = `${request} failed (HTTP ${status})`;
  if (error) message += `: ${error}`;
  if (description) message += ` — ${description}`;
  if (challenge) message += `\nWWW-Authenticate: ${challenge}`;
  return message;
}

function storeOrRemove(key: string, value: string | null): void {
  if (value) {
    localStorage.setItem(key, value);
  } else {
    localStorage.removeItem(key);
  }
}

/**
 * Parses a JSON body, returning null when the response carries something else. Error responses from
 * a proxy or gateway are not always JSON, and a parse failure there must not abort the caller.
 */
async function readJsonOrNull(response: Response): Promise<any> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function parseJsonObject(text: string): Record<string, any> | null {
  try {
    const value = JSON.parse(text);
    return typeof value === 'object' && value !== null ? value : null;
  } catch {
    return null;
  }
}

// Helper function to encode base64URL
function base64URLEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
