import { getOAuthSettings } from '../config/oauth';
import { DPoPService } from './dpopService';

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

export class OAuthService {
  private static instance: OAuthService;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private codeVerifier: string | null = null;
  private state: string | null = null;
  private tokenType: string | null = null;
  private lastDpopProof: string | null = null;
  private dpop = DPoPService.getInstance();

  private constructor() {
    // Load tokens from localStorage on initialization
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
    this.codeVerifier = localStorage.getItem('code_verifier');
    this.state = localStorage.getItem('oauth_state');
    this.tokenType = localStorage.getItem('token_type');
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

  public async getAuthorizationUrl(): Promise<string> {
    const settings = getOAuthSettings();
    this.codeVerifier = this.generateCodeVerifier();
    this.state = this.generateState();
    const codeChallenge = await this.generateCodeChallenge(this.codeVerifier);

    // Store code verifier and state in localStorage
    localStorage.setItem('code_verifier', this.codeVerifier);
    localStorage.setItem('oauth_state', this.state);

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

    return `${settings.baseUrl}${settings.endpoints.authorize}?${params.toString()}`;
  }

  private async requestToken(
    bodyParams: Record<string, unknown>
  ): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    const tokenUrl = `${settings.baseUrl}${settings.endpoints.token}`;

    // Omitting the proof is a request-level fault, so it is handled here rather than in createProof.
    const armedFault = this.dpop.getArmedFault();

    const doRequest = async (nonce?: string) => {
      let dpopProof: string | undefined;
      if (settings.dpopEnabled && armedFault !== 'header-omitted') {
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
      // Read the header before touching the body. A non-JSON error response (proxy down, gateway
      // error) must not cost us the nonce, and RFC 9449 §8.2 obliges the client to adopt it.
      const headerNonce = response.headers.get('dpop-nonce');
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
    if (settings.dpopEnabled && !response.ok && !armedFault) {
      const refreshed = this.dpop.getNonce('as', tokenUrl);
      if (refreshed && refreshed !== currentNonce) {
        ({ response, data } = await doRequest(refreshed));
      }
    }
    if (!response.ok) {
      throw new Error(data?.error || `Token request failed (HTTP ${response.status})`);
    }
    this.setTokens(data);
    return data;
  }

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

  public async getClientCredentialsToken(): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    return this.requestToken({
      clientId: settings.clientId,
      clientSecret: settings.clientSecret,
      grantType: 'client_credentials',
      scope: settings.scope,
    });
  }

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

  /**
   * Calls a protected URL through the proxy using DPoP (when enabled) or Bearer.
   * Handles a single DPoP-Nonce retry on 401. Returns the raw proxy Response.
   */
  public async fetchResource(url: string, method: string = 'GET'): Promise<Response> {
    if (!this.accessToken) {
      throw new Error('No access token available');
    }
    const settings = getOAuthSettings();

    // Omitting the proof is a request-level fault, so it is handled here rather than in createProof.
    const armedFault = this.dpop.getArmedFault();

    const doRequest = async (nonce?: string): Promise<Response> => {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const body: Record<string, unknown> = { url, method };
      if (settings.dpopEnabled && armedFault !== 'header-omitted') {
        const proof = await this.dpop.createProof({
          htu: url,
          htm: method,
          nonce,
          accessToken: this.accessToken!,
        });
        headers['Authorization'] = `DPoP ${this.accessToken}`;
        body.dpopProof = proof;
        this.lastDpopProof = proof;
      } else if (settings.dpopEnabled) {
        // The token still travels as DPoP, so the server rejects the missing proof rather than
        // falling back to treating this as a plain bearer request.
        headers['Authorization'] = `DPoP ${this.accessToken}`;
        this.lastDpopProof = null;
      } else {
        headers['Authorization'] = `Bearer ${this.accessToken}`;
        this.lastDpopProof = null;
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
    if (settings.dpopEnabled && response.status === 401 && !armedFault) {
      const refreshed = this.dpop.getNonce('rs', url);
      if (refreshed && refreshed !== currentNonce) {
        response = await doRequest(refreshed);
      }
    }
    return response;
  }

  public async getProtectedResource(retryOnAuthFailure: boolean = true): Promise<any> {
    if (!this.accessToken) {
      throw new Error('No access token available');
    }
    const settings = getOAuthSettings();
    console.log('Requesting protected resource:', settings.protectedResource);

    try {
      const response = await this.fetchResource(settings.protectedResource, 'GET');
      console.log('Protected resource response status:', response.status);

      if (!response.ok) {
        // A 401 normally means the access token expired, but with a fault armed it is the expected
        // outcome of the resource call itself. Refreshing here would send the same broken proof to
        // the token endpoint and surface that failure instead, hiding the result being tested.
        const armedFault = this.dpop.getArmedFault();
        if (response.status === 401 && this.refreshToken && retryOnAuthFailure && !armedFault) {
          console.log('Access token expired, refreshing...');
          await this.refreshAccessToken();
          // Retry once; pass false to avoid an infinite refresh/retry loop on persistent 401s.
          return this.getProtectedResource(false);
        }
        const errorData = await response.text();
        console.error('Protected resource error:', errorData);
        try {
          const jsonError = JSON.parse(errorData);
          throw new Error(`Failed to get protected resource (HTTP ${response.status}): ${jsonError.error || jsonError.message || errorData || 'Unknown error'}`);
        } catch (e) {
          if (e instanceof Error && e.message.startsWith('Failed to get protected resource')) throw e;
          throw new Error(`Failed to get protected resource (HTTP ${response.status}): ${errorData || response.statusText || 'Unknown error'}`);
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

  private generateState(): string {
    return Math.random().toString(36).substring(7);
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

  public getRefreshToken(): string | null {
    return this.refreshToken;
  }

  private clearAuthData(): void {
    this.codeVerifier = null;
    this.state = null;
    localStorage.removeItem('code_verifier');
    localStorage.removeItem('oauth_state');
  }

  public clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenType = null;
    this.clearAuthData();
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('token_type');
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

// Helper function to encode base64URL
function base64URLEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}