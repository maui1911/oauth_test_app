import { getOAuthSettings } from '../config/oauth';

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

  private constructor() {
    // Load tokens from localStorage on initialization
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
    this.codeVerifier = localStorage.getItem('code_verifier');
    this.state = localStorage.getItem('oauth_state');
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

    return `${settings.baseUrl}${settings.endpoints.authorize}?${params.toString()}`;
  }

  public async exchangeCodeForTokens(code: string, state: string): Promise<TokenResponse> {
    // Verify state matches
    if (state !== this.state) {
      throw new Error('Invalid state parameter');
    }

    if (!this.codeVerifier) {
      throw new Error('Code verifier not found. Please start the authorization flow again.');
    }

    const settings = getOAuthSettings();
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: settings.clientId,
      client_secret: settings.clientSecret,
      redirect_uri: settings.redirectUri,
      code_verifier: this.codeVerifier,
    });

    const response = await fetch(`${settings.baseUrl}${settings.endpoints.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error('Failed to exchange code for tokens');
    }

    const data = await response.json();
    this.setTokens(data);
    this.clearAuthData(); // Clear code verifier and state after successful exchange
    return data;
  }

  public async getClientCredentialsToken(): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: settings.clientId,
      client_secret: settings.clientSecret,
      scope: settings.scope,
    });

    const response = await fetch(`${settings.baseUrl}${settings.endpoints.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error('Failed to get client credentials token');
    }

    const data = await response.json();
    this.setTokens(data);
    return data;
  }

  public async refreshAccessToken(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const settings = getOAuthSettings();
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this.refreshToken,
      client_id: settings.clientId,
      client_secret: settings.clientSecret,
    });

    const response = await fetch(`${settings.baseUrl}${settings.endpoints.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error('Failed to refresh token');
    }

    const data = await response.json();
    this.setTokens(data);
    return data;
  }

  public async getProtectedResource(): Promise<any> {
    if (!this.accessToken) {
      throw new Error('No access token available');
    }

    const settings = getOAuthSettings();
    const response = await fetch(settings.protectedResource, {
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
      },
    });

    if (!response.ok) {
      if (response.status === 401 && this.refreshToken) {
        // Token expired, try to refresh
        await this.refreshAccessToken();
        return this.getProtectedResource();
      }
      throw new Error('Failed to get protected resource');
    }

    return response.json();
  }

  private setTokens(data: TokenResponse): void {
    this.accessToken = data.access_token;
    if (data.refresh_token) {
      this.refreshToken = data.refresh_token;
    }

    // Store tokens in localStorage
    localStorage.setItem('access_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
  }

  private generateState(): string {
    return Math.random().toString(36).substring(7);
  }

  public getAccessToken(): string | null {
    return this.accessToken;
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
    this.clearAuthData();
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }
}

// Helper function to encode base64URL
function base64URLEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
} 